import logging
import json
import re
import ipaddress
import math
from collections import Counter
from typing import Any, Dict, List, Optional

from blackwall.models import ToolCallContext, VerdictDecision, IndicatorType
from blackwall.policy.models import GateResult, StructuralAction
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.mcp.gti_client import GTIMCPClient, GTIDegradedError, GTIQueryBudgetTracker
from blackwall.mcp.codebase_memory import CodebaseMemoryClient

logger = logging.getLogger("blackwall.policy.semantic")

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")


def extract_strings(val: Any) -> List[str]:
    strings = []
    if isinstance(val, str):
        strings.append(val)
    elif isinstance(val, dict):
        for v in val.values():
            strings.extend(extract_strings(v))
    elif isinstance(val, (list, tuple, set)):
        for v in val:
            strings.extend(extract_strings(v))
    return strings


def extract_iocs(context: ToolCallContext) -> Dict[str, List[str]]:
    iocs: Dict[str, List[str]] = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": []
    }
    all_strings = extract_strings(context.arguments)
    all_strings.append(context.tool_name)

    for s in all_strings:
        # Extract IPs
        for ip in IP_PATTERN.findall(s):
            parts = ip.split(".")
            if all(0 <= int(part) <= 255 for part in parts):
                iocs["ips"].append(ip)

        # Extract URLs
        for url in URL_PATTERN.findall(s):
            iocs["urls"].append(url)

        # Extract Hashes
        for h in HASH_PATTERN.findall(s):
            iocs["hashes"].append(h)

        # Extract Domains
        for dom in DOMAIN_PATTERN.findall(s):
            if not IP_PATTERN.match(dom):
                iocs["domains"].append(dom)

    # Deduplicate
    for k in iocs:
        iocs[k] = list(set(iocs[k]))
    return iocs


def is_external_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        return False


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


class SemanticGatingEngine:
    """
    Semantic gating engine that evaluates tool calls using multi-source signals:
    Threat Signature Graph, GTI, Codebase-Memory (CBM), and context.
    """

    def __init__(
        self,
        repo: Optional[SQLiteThreatRepository] = None,
        gti_client: Optional[GTIMCPClient] = None,
        cbm_client: Optional[CodebaseMemoryClient] = None,
        budget_tracker: Optional[GTIQueryBudgetTracker] = None,
    ) -> None:
        self.repo = repo
        self.gti_client = gti_client
        self.cbm_client = cbm_client
        self.budget_tracker = budget_tracker or (gti_client.budget_tracker if gti_client else None)

    async def is_high_risk(
        self,
        context: ToolCallContext,
        iocs: Dict[str, List[str]],
        structural_result: Optional[Any] = None,
    ) -> bool:
        # Check structural gating signals indicating elevated threat
        if structural_result:
            if structural_result.decision == StructuralAction.ESCALATE_TO_SEMANTIC:
                return True
            if getattr(structural_result, "requireSemanticReview", False):
                return True

        # Check new external IPs not in cache
        for ip in iocs.get("ips", []):
            if is_external_ip(ip):
                if self.repo:
                    cached = await self.repo.get_cached_gti_response(ip, IndicatorType.IP_ADDRESS.value)
                    if not cached:
                        return True
                else:
                    return True

        # Check suspicious file hashes
        for h in iocs.get("hashes", []):
            if self.repo:
                cached = await self.repo.get_cached_gti_response(h, IndicatorType.FILE_HASH.value)
                if not cached:
                    return True
            else:
                return True

        # Check unknown domains
        for domain in iocs.get("domains", []):
            if self.repo:
                cached = await self.repo.get_cached_gti_response(domain, IndicatorType.DOMAIN.value)
                if not cached:
                    return True
            else:
                return True

        return False

    async def calculate_suspicion_score(
        self,
        context: ToolCallContext,
        iocs: Dict[str, List[str]],
        structural_result: Optional[Any] = None,
    ) -> float:
        score = 0.0

        # 1. IOC Novelty (not in local cache) - max 0.3
        novelty_points = 0.0
        for ip in iocs.get("ips", []):
            if is_external_ip(ip):
                if self.repo:
                    cached = await self.repo.get_cached_gti_response(ip, IndicatorType.IP_ADDRESS.value)
                    if not cached:
                        novelty_points = 0.3
                        break
                else:
                    novelty_points = 0.3
                    break
        for h in iocs.get("hashes", []):
            if self.repo:
                cached = await self.repo.get_cached_gti_response(h, IndicatorType.FILE_HASH.value)
                if not cached:
                    novelty_points = 0.3
                    break
            else:
                novelty_points = 0.3
                break
        for domain in iocs.get("domains", []):
            if self.repo:
                cached = await self.repo.get_cached_gti_response(domain, IndicatorType.DOMAIN.value)
                if not cached:
                    novelty_points = 0.3
                    break
            else:
                novelty_points = 0.3
                break
        score += novelty_points

        # 2. Domain Reputation Signals - max 0.2
        domain_points = 0.0
        suspicious_tlds = {".xyz", ".top", ".zip", ".win", ".info", ".biz", ".cc", ".icu", ".gdn", ".cn"}
        for domain in iocs.get("domains", []):
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                domain_points = 0.2
                break
            # Or if it's unknown/not in cache, reputation is suspicious
            if self.repo:
                cached = await self.repo.get_cached_gti_response(domain, IndicatorType.DOMAIN.value)
                if not cached:
                    domain_points = 0.15
            else:
                domain_points = 0.15
        score += domain_points

        # 3. IP Geolocation Risk - max 0.2
        geo_points = 0.0
        for ip in iocs.get("ips", []):
            if is_external_ip(ip):
                geo = ""
                if context.metadata:
                    geo = context.metadata.get("country", "") or context.metadata.get("geolocation", "")
                if geo in ["RU", "CN", "KP", "IR", "BY"]:
                    geo_points = 0.2
                else:
                    geo_points = 0.1
                break
        score += geo_points

        # 4. File Hash Entropy - max 0.15
        entropy_points = 0.0
        for h in iocs.get("hashes", []):
            ent = calculate_entropy(h)
            if ent > 3.0:
                entropy_points = 0.15
                break
            elif ent > 0.0:
                entropy_points = 0.1
        score += entropy_points

        # 5. Structural Policy Rule Violations - max 0.15
        struct_points = 0.0
        if structural_result:
            if structural_result.decision == StructuralAction.ESCALATE_TO_SEMANTIC:
                struct_points = 0.15
            elif getattr(structural_result, "requireSemanticReview", False):
                struct_points = 0.1
        score += struct_points

        return min(1.0, score)

    async def evaluate(
        self,
        context: ToolCallContext,
        environment_role: str,
        structural_result: Optional[Any] = None,
    ) -> GateResult:
        """
        Evaluates a tool call context semantically.
        """
        # 1. Query Threat Signature Graph first (cheapest check)
        if self.repo:
            matched_sig = await self.repo.find_matching_signature(
                context.tool_name, context.arguments
            )
            if matched_sig:
                return GateResult(
                    verdict=VerdictDecision.BLOCK,
                    reason=f"Matched threat signature: {matched_sig['attacker_intent']}",
                    threat_score=1.0,
                    signature_id=matched_sig["signature_id"],
                )

        # 2. Extract IOCs and query GTI MCP
        iocs = extract_iocs(context)
        
        is_high = await self.is_high_risk(context, iocs, structural_result)
        suspicion_score = await self.calculate_suspicion_score(context, iocs, structural_result)

        gti_responses = []
        gti_degraded = False
        gti_error = False
        gti_budget_exhausted = False

        if self.gti_client and is_high:
            try:
                for ip in iocs["ips"]:
                    if self.budget_tracker:
                        # Check cache first to avoid consuming budget
                        cached = await self.repo.get_cached_gti_response(ip, IndicatorType.IP_ADDRESS.value) if self.repo else None
                        if cached:
                            gti_responses.append(GTIResponse.model_validate(cached))
                            self.budget_tracker.metrics.cacheHits += 1
                            continue
                        
                        if not await self.budget_tracker.tryAcquire():
                            gti_budget_exhausted = True
                            break
                    resp = await self.gti_client.queryIOC(ip, IndicatorType.IP_ADDRESS, skip_budget_check=True)
                    gti_responses.append(resp)
                
                for url in iocs["urls"]:
                    if not gti_budget_exhausted:
                        if self.budget_tracker:
                            cached = await self.repo.get_cached_gti_response(url, IndicatorType.URL.value) if self.repo else None
                            if cached:
                                gti_responses.append(GTIResponse.model_validate(cached))
                                self.budget_tracker.metrics.cacheHits += 1
                                continue
                            
                            if not await self.budget_tracker.tryAcquire():
                                gti_budget_exhausted = True
                                break
                        resp = await self.gti_client.queryIOC(url, IndicatorType.URL, skip_budget_check=True)
                        gti_responses.append(resp)

                for domain in iocs["domains"]:
                    if not gti_budget_exhausted:
                        if not any(domain in u for u in iocs["urls"]):
                            if self.budget_tracker:
                                cached = await self.repo.get_cached_gti_response(domain, IndicatorType.DOMAIN.value) if self.repo else None
                                if cached:
                                    gti_responses.append(GTIResponse.model_validate(cached))
                                    self.budget_tracker.metrics.cacheHits += 1
                                    continue
                                
                                if not await self.budget_tracker.tryAcquire():
                                    gti_budget_exhausted = True
                                    break
                            resp = await self.gti_client.queryIOC(domain, IndicatorType.DOMAIN, skip_budget_check=True)
                            gti_responses.append(resp)

                for h in iocs["hashes"]:
                    if not gti_budget_exhausted:
                        if self.budget_tracker:
                            cached = await self.repo.get_cached_gti_response(h, IndicatorType.FILE_HASH.value) if self.repo else None
                            if cached:
                                gti_responses.append(GTIResponse.model_validate(cached))
                                self.budget_tracker.metrics.cacheHits += 1
                                continue
                            
                            if not await self.budget_tracker.tryAcquire():
                                gti_budget_exhausted = True
                                break
                        resp = await self.gti_client.queryIOC(h, IndicatorType.FILE_HASH, skip_budget_check=True)
                        gti_responses.append(resp)

            except GTIDegradedError:
                gti_degraded = True
            except Exception as e:
                logger.error("Error querying GTI MCP: %s", e)
                gti_error = True

        gti_unavailable = gti_degraded or gti_budget_exhausted or gti_error
        gti_penalty = 0.2 if gti_unavailable else 0.0

        # Calculate GTI Score
        gti_score: Optional[float] = None
        if self.gti_client and not gti_unavailable:
            if not gti_responses:
                gti_score = 0.0
            else:
                scores = []
                for r in gti_responses:
                    s = 0.0
                    if r.is_malicious:
                        s += 0.5
                    s += 0.3 * (r.detection_rate / 100.0)
                    if r.threat_categories:
                        s += min(len(r.threat_categories) * 0.1, 0.2)
                    scores.append(min(s, 1.0))
                gti_score = max(scores) if scores else 0.0

        # 3. Query Codebase-Memory MCP
        cbm_score: Optional[float] = None
        cbm_penalty = 0.0
        cbm_error = False

        target_func = None
        if hasattr(context, "targetFunction") and getattr(context, "targetFunction"):
            target_func = getattr(context, "targetFunction")
        elif "targetFunction" in context.arguments:
            target_func = context.arguments["targetFunction"]

        if self.cbm_client and target_func:
            try:
                dep_chain = await self.cbm_client.queryDependencyChain(target_func)
                blast_radius = await self.cbm_client.getBlastRadius(target_func)
                sinks = await self.cbm_client.identifyCriticalSinks(target_func)
                unsafe_sinks = self.cbm_client.identifyUnsafeSinks(sinks)

                s_cbm = 0.0
                if dep_chain.hasCriticalSink:
                    s_cbm += 0.4
                if unsafe_sinks:
                    s_cbm += 0.3
                s_cbm += 0.3 * blast_radius.riskScore

                cbm_score = min(s_cbm, 1.0)
                cbm_penalty = self.cbm_client.get_threat_score_penalty()
            except Exception as e:
                logger.error("Error querying CBM MCP: %s", e)

        # 4. Context Score
        # Tool risk
        tool_risk = 0.2
        if context.tool_name == "run_command":
            tool_risk = 1.0
        elif context.tool_name in ("write_to_file", "multi_replace_file_content", "replace_file_content", "git"):
            tool_risk = 0.7

        # Argument novelty / suspicious patterns
        args_str = json.dumps(context.arguments)
        suspicious_patterns = (
            "rm -rf", "sudo", "curl", "wget", "/etc/passwd", "chmod", "chown", "nc ", "/root", ".ssh", "|", ">", "<"
        )
        argument_novelty = 0.0
        if any(p in args_str for p in suspicious_patterns):
            argument_novelty = 1.0

        # Environment role risk
        env_risk = 0.5
        if environment_role == "production":
            env_risk = 1.0
        elif environment_role == "sandbox":
            env_risk = 0.2

        context_score = 0.4 * tool_risk + 0.3 * argument_novelty + 0.3 * env_risk

        # 5. Signal Aggregation & Normalization
        threat_score = self.computeThreatScore(
            gti_score=gti_score,
            cbm_score=cbm_score,
            context_score=context_score,
            gti_penalty=gti_penalty,
            cbm_penalty=cbm_penalty,
            gti_unavailable=gti_unavailable,
        )

        # Verdict
        if threat_score >= 0.75:
            verdict = VerdictDecision.BLOCK
            reason = "Threat score exceeds BLOCK threshold."
        elif threat_score >= 0.5:
            verdict = VerdictDecision.QUARANTINE
            reason = "Threat score exceeds QUARANTINE threshold."
        else:
            verdict = VerdictDecision.ALLOW
            reason = "Threat score within normal limits."

        return GateResult(
            verdict=verdict,
            reason=reason,
            threat_score=threat_score,
        )

    def computeThreatScore(
        self,
        gti_score: Optional[float],
        cbm_score: Optional[float],
        context_score: float,
        gti_penalty: float = 0.0,
        cbm_penalty: float = 0.0,
        gti_unavailable: bool = False,
    ) -> float:
        """
        Computes the final threat score by aggregating available signals.
        """
        signals = {
            "gti": gti_score if not gti_unavailable else None,
            "cbm": cbm_score,
            "context": context_score,
        }

        base_weights = {
            "gti": 0.4,
            "cbm": 0.3,
            "context": 0.3,
        }

        if gti_unavailable:
            base_weights["gti"] = 0.0
            base_weights["cbm"] = 0.5
            base_weights["context"] = 0.5

        available_signals = {k: v for k, v in signals.items() if v is not None}
        total_weight = sum(base_weights[k] for k in available_signals.keys())

        if total_weight == 0.0:
            score = context_score
        else:
            score = 0.0
            for k, v in available_signals.items():
                weight = base_weights[k] / total_weight
                score += weight * v

        score += gti_penalty
        score += cbm_penalty

        return max(0.0, min(score, 1.0))

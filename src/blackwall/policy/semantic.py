import asyncio
import inspect
import logging
import json
import re
import ipaddress
import math
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, ClassVar, Dict, List, Optional

from pydantic import BaseModel, Field

from blackwall.config import (
    DEFAULT_RAPID_TRIAGE_MODEL,
    get_gemini_http_timeout,
    get_gemini_thinking_level,
)
from blackwall.models import (
    ToolCallContext,
    VerdictDecision,
    IndicatorType,
    GTIResponse,
)
from blackwall.policy.models import GateResult, StructuralAction
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.mcp.codebase_memory import CodebaseMemoryClient
from blackwall.validators import clamp_score, normalize_text

try:
    try:
        from blackwall import _core_rs
    except ImportError:
        import _core_rs
except (ImportError, AttributeError):
    _core_rs = None

logger = logging.getLogger("blackwall.policy.semantic")

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
)
HIGH_RISK_GEOLOCATIONS = frozenset({"RU", "CN", "KP", "IR", "BY"})


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
    all_strings = extract_strings(context.arguments)
    all_strings.append(context.tool_name)

    if _core_rs is not None and hasattr(_core_rs, "extract_iocs"):
        try:
            raw_iocs = _core_rs.extract_iocs(all_strings)
            return {k: list(v) for k, v in raw_iocs.items()}
        except Exception:
            pass

    iocs: Dict[str, List[str]] = {"ips": [], "domains": [], "urls": [], "hashes": []}
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
    if _core_rs is not None and hasattr(_core_rs, "calculate_entropy"):
        try:
            return float(_core_rs.calculate_entropy(s))
        except Exception:
            pass
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


class SemanticGatingEngine:
    """
    Semantic gating engine that evaluates tool calls using multi-source signals:
    Threat Signature Graph, Threat Intelligence, Codebase-Memory (CBM), and context.
    """

    def __init__(
        self,
        repo: Optional[SQLiteThreatRepository] = None,
        gti_client: Optional[Any] = None,
        cbm_client: Optional[CodebaseMemoryClient] = None,
        budget_tracker: Optional[Any] = None,
        threat_intel_client: Optional[Any] = None,
    ) -> None:
        self.repo = repo
        self.threat_intel_client = threat_intel_client or gti_client
        self.gti_client = self.threat_intel_client
        self.cbm_client = cbm_client
        self.budget_tracker = budget_tracker or getattr(self.threat_intel_client, "budget_tracker", None)

    def apply_policy_mcp_config(self, mcp_config: Any) -> None:
        """Applies MCP server configurations from policy to active MCP clients."""
        if not mcp_config:
            return
        ti_conf = getattr(mcp_config, "threatIntel", None) or getattr(mcp_config, "gti", None)
        if ti_conf and getattr(ti_conf, "url", None) and self.threat_intel_client:
            if hasattr(self.threat_intel_client, "base_url"):
                self.threat_intel_client.base_url = ti_conf.url
        cbm_conf = getattr(mcp_config, "codebaseMemory", None)
        if cbm_conf and getattr(cbm_conf, "url", None) and self.cbm_client:
            if hasattr(self.cbm_client, "base_url"):
                self.cbm_client.base_url = cbm_conf.url

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
                    cached = await self.repo.get_cached_threat_intel_response(
                        ip, IndicatorType.IP_ADDRESS.value
                    )
                    if not cached:
                        return True
                else:
                    return True

        # Check suspicious file hashes
        for h in iocs.get("hashes", []):
            if self.repo:
                cached = await self.repo.get_cached_threat_intel_response(
                    h, IndicatorType.FILE_HASH.value
                )
                if not cached:
                    return True
            else:
                return True

        # Check unknown domains
        for domain in iocs.get("domains", []):
            if self.repo:
                cached = await self.repo.get_cached_threat_intel_response(
                    domain, IndicatorType.DOMAIN.value
                )
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
                    cached = await self.repo.get_cached_threat_intel_response(
                        ip, IndicatorType.IP_ADDRESS.value
                    )
                    if not cached:
                        novelty_points = 0.3
                        break
                else:
                    novelty_points = 0.3
                    break
        for h in iocs.get("hashes", []):
            if self.repo:
                cached = await self.repo.get_cached_threat_intel_response(
                    h, IndicatorType.FILE_HASH.value
                )
                if not cached:
                    novelty_points = 0.3
                    break
            else:
                novelty_points = 0.3
                break
        for domain in iocs.get("domains", []):
            if self.repo:
                cached = await self.repo.get_cached_threat_intel_response(
                    domain, IndicatorType.DOMAIN.value
                )
                if not cached:
                    novelty_points = 0.3
                    break
            else:
                novelty_points = 0.3
                break
        score += novelty_points

        # 2. Domain Reputation Signals - max 0.2
        domain_points = 0.0
        suspicious_tlds = {
            ".xyz",
            ".top",
            ".zip",
            ".win",
            ".info",
            ".biz",
            ".cc",
            ".icu",
            ".gdn",
            ".cn",
        }
        for domain in iocs.get("domains", []):
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                domain_points = 0.2
                break
            # Or if it's unknown/not in cache, reputation is suspicious
            if self.repo:
                cached = await self.repo.get_cached_gti_response(
                    domain, IndicatorType.DOMAIN.value
                )
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
                    geo = context.metadata.get("country", "") or context.metadata.get(
                        "geolocation", ""
                    )
                if geo in HIGH_RISK_GEOLOCATIONS:
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

        # 2. Extract IOCs and query Threat Intelligence MCP
        iocs = extract_iocs(context)

        is_high = await self.is_high_risk(context, iocs, structural_result)

        threat_intel_responses = []
        threat_intel_degraded = False
        threat_intel_budget_exhausted = False
        threat_intel_error = False

        ti_client = self.threat_intel_client or self.gti_client
        if ti_client and is_high:
            try:
                for ip in iocs["ips"]:
                    cached = None
                    if self.repo:
                        cached = await self.repo.get_cached_threat_intel_response(
                            ip, IndicatorType.IP_ADDRESS.value
                        ) or await self.repo.get_cached_threat_intel_response(
                            ip, IndicatorType.IP_ADDRESS.value.lower()
                        )
                    if cached:
                        try:
                            # Use cached payload directly instead of re-querying
                            resp = GTIResponse(
                                indicator=cached.get("indicator", ip),
                                is_malicious=cached.get("is_malicious", False),
                                threat_categories=cached.get("threat_categories", []),
                                detection_rate=cached.get("detection_rate", 0.0),
                                confidence=cached.get("confidence", 0.0),
                                last_analysis_date=cached.get("last_analysis_date"),
                                related_campaigns=cached.get("related_campaigns", []),
                            )
                            threat_intel_responses.append(resp)
                        except Exception as e:
                            logger.error("Error parsing cached IP response: %s", e)
                        continue

                    if threat_intel_budget_exhausted:
                        continue

                    if self.budget_tracker:
                        if not await self.budget_tracker.try_acquire():
                            threat_intel_budget_exhausted = True
                            continue
                    try:
                        if hasattr(ti_client, "queryIOC"):
                            resp = await ti_client.queryIOC(
                                ip,
                                IndicatorType.IP_ADDRESS,
                                skip_budget_check=(self.budget_tracker is not None),
                            )
                        elif hasattr(ti_client, "lookup"):
                            resp = await ti_client.lookup(ip, IndicatorType.IP_ADDRESS.value)
                        elif hasattr(ti_client, "query"):
                            resp = await ti_client.query(ip)
                        else:
                            resp = None
                        if resp is not None:
                            threat_intel_responses.append(resp)
                    except Exception as e:
                        err_name = type(e).__name__
                        if "Degraded" in err_name or "CircuitBreaker" in err_name:
                            threat_intel_degraded = True
                        elif "Budget" in err_name or "Exhausted" in err_name:
                            threat_intel_budget_exhausted = True
                        else:
                            logger.error("Error querying IP: %s", e)
                            threat_intel_error = True

                for url in iocs["urls"]:
                    cached = None
                    if self.repo:
                        cached = await self.repo.get_cached_threat_intel_response(
                            url, IndicatorType.URL.value
                        ) or await self.repo.get_cached_threat_intel_response(
                            url, IndicatorType.URL.value.lower()
                        )
                    if cached:
                        try:
                            # Use cached payload directly instead of re-querying
                            resp = GTIResponse(
                                indicator=cached.get("indicator", url),
                                is_malicious=cached.get("is_malicious", False),
                                threat_categories=cached.get("threat_categories", []),
                                detection_rate=cached.get("detection_rate", 0.0),
                                confidence=cached.get("confidence", 0.0),
                                last_analysis_date=cached.get("last_analysis_date"),
                                related_campaigns=cached.get("related_campaigns", []),
                            )
                            threat_intel_responses.append(resp)
                        except Exception as e:
                            logger.error("Error parsing cached URL response: %s", e)
                        continue

                    if threat_intel_budget_exhausted:
                        continue

                    if self.budget_tracker:
                        if not await self.budget_tracker.try_acquire():
                            threat_intel_budget_exhausted = True
                            continue
                    try:
                        if hasattr(ti_client, "queryIOC"):
                            resp = await ti_client.queryIOC(
                                url,
                                IndicatorType.URL,
                                skip_budget_check=(self.budget_tracker is not None),
                            )
                        elif hasattr(ti_client, "lookup"):
                            resp = await ti_client.lookup(url, IndicatorType.URL.value)
                        elif hasattr(ti_client, "query"):
                            resp = await ti_client.query(url)
                        else:
                            resp = None
                        if resp is not None:
                            threat_intel_responses.append(resp)
                    except Exception as e:
                        err_name = type(e).__name__
                        if "Degraded" in err_name or "CircuitBreaker" in err_name:
                            threat_intel_degraded = True
                        elif "Budget" in err_name or "Exhausted" in err_name:
                            threat_intel_budget_exhausted = True
                        else:
                            logger.error("Error querying URL: %s", e)
                            threat_intel_error = True

                for domain in iocs["domains"]:
                    if not any(domain in u for u in iocs["urls"]):
                        cached = None
                        if self.repo:
                            cached = await self.repo.get_cached_threat_intel_response(
                                domain, IndicatorType.DOMAIN.value
                            ) or await self.repo.get_cached_threat_intel_response(
                                domain, IndicatorType.DOMAIN.value.lower()
                            )
                        if cached:
                            try:
                                # Use cached payload directly instead of re-querying
                                resp = GTIResponse(
                                    indicator=cached.get("indicator", domain),
                                    is_malicious=cached.get("is_malicious", False),
                                    threat_categories=cached.get(
                                        "threat_categories", []
                                    ),
                                    detection_rate=cached.get("detection_rate", 0.0),
                                    confidence=cached.get("confidence", 0.0),
                                    last_analysis_date=cached.get("last_analysis_date"),
                                    related_campaigns=cached.get(
                                        "related_campaigns", []
                                    ),
                                )
                                threat_intel_responses.append(resp)
                            except Exception as e:
                                logger.error(
                                    "Error parsing cached domain response: %s", e
                                )
                            continue

                        if threat_intel_budget_exhausted:
                            continue

                        if self.budget_tracker:
                            if not await self.budget_tracker.try_acquire():
                                threat_intel_budget_exhausted = True
                                continue
                        try:
                            if hasattr(ti_client, "queryIOC"):
                                resp = await ti_client.queryIOC(
                                    domain,
                                    IndicatorType.DOMAIN,
                                    skip_budget_check=(self.budget_tracker is not None),
                                )
                            elif hasattr(ti_client, "lookup"):
                                resp = await ti_client.lookup(domain, IndicatorType.DOMAIN.value)
                            elif hasattr(ti_client, "query"):
                                resp = await ti_client.query(domain)
                            else:
                                resp = None
                            if resp is not None:
                                threat_intel_responses.append(resp)
                        except Exception as e:
                            err_name = type(e).__name__
                            if "Degraded" in err_name or "CircuitBreaker" in err_name:
                                threat_intel_degraded = True
                            elif "Budget" in err_name or "Exhausted" in err_name:
                                threat_intel_budget_exhausted = True
                            else:
                                logger.error("Error querying domain: %s", e)
                                threat_intel_error = True

                for h in iocs["hashes"]:
                    cached = None
                    if self.repo:
                        cached = await self.repo.get_cached_threat_intel_response(
                            h, IndicatorType.FILE_HASH.value
                        ) or await self.repo.get_cached_threat_intel_response(
                            h, IndicatorType.FILE_HASH.value.lower()
                        )
                    if cached:
                        try:
                            # Use cached payload directly instead of re-querying
                            resp = GTIResponse(
                                indicator=cached.get("indicator", h),
                                is_malicious=cached.get("is_malicious", False),
                                threat_categories=cached.get("threat_categories", []),
                                detection_rate=cached.get("detection_rate", 0.0),
                                confidence=cached.get("confidence", 0.0),
                                last_analysis_date=cached.get("last_analysis_date"),
                                related_campaigns=cached.get("related_campaigns", []),
                            )
                            threat_intel_responses.append(resp)
                        except Exception as e:
                            logger.error("Error parsing cached hash response: %s", e)
                        continue

                    if threat_intel_budget_exhausted:
                        continue

                    if self.budget_tracker:
                        if not await self.budget_tracker.try_acquire():
                            threat_intel_budget_exhausted = True
                            continue
                    try:
                        if hasattr(ti_client, "queryIOC"):
                            resp = await ti_client.queryIOC(
                                h,
                                IndicatorType.FILE_HASH,
                                skip_budget_check=(self.budget_tracker is not None),
                            )
                        elif hasattr(ti_client, "lookup"):
                            resp = await ti_client.lookup(h, IndicatorType.FILE_HASH.value)
                        elif hasattr(ti_client, "query"):
                            resp = await ti_client.query(h)
                        else:
                            resp = None
                        if resp is not None:
                            threat_intel_responses.append(resp)
                    except Exception as e:
                        err_name = type(e).__name__
                        if "Degraded" in err_name or "CircuitBreaker" in err_name:
                            threat_intel_degraded = True
                        elif "Budget" in err_name or "Exhausted" in err_name:
                            threat_intel_budget_exhausted = True
                        else:
                            logger.error("Error querying hash: %s", e)
                            threat_intel_error = True
            except Exception as e:
                logger.error("Error in IOC query loop: %s", e)
                threat_intel_error = True

        # Apply penalty only for degraded or budget exhaustion (not for general errors)
        threat_intel_penalty = (
            0.2 if (threat_intel_degraded or threat_intel_budget_exhausted) else 0.0
        )

        # Calculate Threat Intelligence Score
        threat_intel_score: Optional[float] = None
        if ti_client and threat_intel_responses:
            scores = []
            for r in threat_intel_responses:
                s = 0.0
                if getattr(r, "is_malicious", False):
                    s += 0.5
                det_rate = getattr(r, "detection_rate", 0.0)
                risk = getattr(r, "risk_score", None)
                if risk is not None:
                    s += 0.5 * risk
                else:
                    s += 0.3 * (det_rate / 100.0)
                cats = getattr(r, "threat_categories", [])
                if cats:
                    s += min(len(cats) * 0.1, 0.2)
                scores.append(min(s, 1.0))
            threat_intel_score = max(scores) if scores else 0.0
        # Note: Do NOT assign synthetic 0.0 when Threat Intel is available but not applicable
        # Leave threat_intel_score as None so weight redistribution occurs properly

        # 3. Query Codebase-Memory MCP
        cbm_score: Optional[float] = None
        cbm_penalty = 0.0

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
        elif context.tool_name in (
            "write_to_file",
            "multi_replace_file_content",
            "replace_file_content",
            "git",
        ):
            tool_risk = 0.7

        # Argument novelty / suspicious patterns
        args_str = json.dumps(context.arguments)
        suspicious_patterns = (
            "rm -rf",
            "sudo",
            "curl",
            "wget",
            "/etc/passwd",
            "chmod",
            "chown",
            "nc ",
            "/root",
            ".ssh",
            "|",
            ">",
            "<",
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
        # Threat Intel is only considered unavailable if we have no responses at all due to errors/degradation
        threat_intel_unavailable = (threat_intel_score is None) and (
            threat_intel_degraded or threat_intel_budget_exhausted or threat_intel_error
        )
        threat_score = self.computeThreatScore(
            threat_intel_score=threat_intel_score,
            cbm_score=cbm_score,
            context_score=context_score,
            threat_intel_penalty=threat_intel_penalty,
            cbm_penalty=cbm_penalty,
            threat_intel_unavailable=threat_intel_unavailable,
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
        gti_score: Optional[float] = None,
        cbm_score: Optional[float] = None,
        context_score: float = 0.0,
        suspicion_score: float = 0.0,
        gti_penalty: float = 0.0,
        cbm_penalty: float = 0.0,
        gti_unavailable: bool = False,
        threat_intel_score: Optional[float] = None,
        threat_intel_penalty: float = 0.0,
        threat_intel_unavailable: Optional[bool] = None,
        **kwargs: Any,
    ) -> float:
        """
        Computes the final threat score by aggregating available signals.
        """
        ti_score = threat_intel_score if threat_intel_score is not None else gti_score
        ti_penalty = (
            threat_intel_penalty if threat_intel_penalty != 0.0 else gti_penalty
        )
        ti_unavailable = (
            threat_intel_unavailable
            if threat_intel_unavailable is not None
            else gti_unavailable
        )

        signals = {
            "threat_intel": ti_score if not ti_unavailable else None,
            "cbm": cbm_score,
            "context": context_score,
        }

        base_weights = {
            "threat_intel": 0.4,
            "cbm": 0.3,
            "context": 0.3,
        }

        if ti_unavailable or ti_score is None:
            # Threat Intel is unavailable: redistribute weight (40%) to CBM (+20%) and Context (+20%)
            base_weights["threat_intel"] = 0.0
            base_weights["cbm"] = 0.5
            base_weights["context"] = 0.5

        # Filter signals that are not None and have non-zero weight
        available_signals = {
            k: v for k, v in signals.items() if v is not None and base_weights[k] > 0.0
        }
        total_weight = sum(base_weights[k] for k in available_signals.keys())

        if total_weight == 0.0:
            score = context_score
        else:
            score = 0.0
            for k, v in available_signals.items():
                weight = base_weights[k] / total_weight
                score += weight * v

        score += ti_penalty
        score += cbm_penalty

        return clamp_score(score)


# ---------------------------------------------------------------------------
# Tier-1 semantic triage provider seam
# (.kiro/specs/tier-1-jev-addition/ — FR-01)
# ---------------------------------------------------------------------------

SEMANTIC_BACKEND_ENV_VAR = "BW_SEMANTIC_BACKEND"
DEFAULT_SEMANTIC_BACKEND = "gemini"

# Backends named by FR-01 that remain unimplemented until their owning task.
# They resolve to DEFAULT_SEMANTIC_BACKEND rather than raising or disabling
# triage, which would be fail-open relative to the pre-seam behaviour.
PENDING_SEMANTIC_BACKENDS: frozenset[str] = frozenset({"jev"})


class SemanticTriageEvaluation(BaseModel):
    threat_score: float = Field(
        ..., ge=0.0, le=1.0, description="Risk assessment score between 0.0 and 1.0"
    )
    is_suspicious: bool = Field(
        ..., description="Whether the tool call exhibits malicious intent"
    )
    reasoning: str = Field(..., description="Concise rationale for the verdict")


@dataclass(frozen=True, slots=True)
class SemanticTriageResult:
    """Backend-agnostic Tier-1 signal handed to Score Aggregation.

    Only ``threat_score`` is consumed today; the remaining fields are the
    contract Tracks B/C add on top of this seam.
    """

    threat_score: float
    confidence: Optional[float] = None
    """Calibration confidence — populated by the Jev backend (FR-07)."""

    backend: str = DEFAULT_SEMANTIC_BACKEND
    escalate: bool = False
    """Ambiguity-band flag — consumed by Tier-2 routing (FR-03)."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "threat_score", clamp_score(float(self.threat_score)))
        if self.confidence is not None:
            object.__setattr__(self, "confidence", clamp_score(float(self.confidence)))
        if not normalize_text(self.backend):
            raise ValueError("SemanticTriageResult.backend must be a non-empty string")


class SemanticTriageProvider(ABC):
    """Pluggable Tier-1 semantic triage backend (``jev`` | ``gemini``)."""

    name: ClassVar[str] = ""

    @abstractmethod
    async def triage(self, context: ToolCallContext) -> Optional[SemanticTriageResult]:
        """Evaluate a tool call, or return None when no signal is available.

        None means "abstain" and is deliberately distinct from a
        ``threat_score`` of 0.0: the fail-closed ``max()`` in
        ``SyncResolver._score_argument_novelty`` must not let a synthetic zero
        mask a deterministic high-risk signal.
        """


class GeminiTriageBackend(SemanticTriageProvider):
    """Gemini 3.5 Flash-Lite rapid triage — behaviour-preserving port of the
    inline call that previously lived in ``SyncResolver._evaluate_semantic_intent``.
    """

    name: ClassVar[str] = "gemini"

    def __init__(
        self,
        client: Any,
        *,
        model: str = DEFAULT_RAPID_TRIAGE_MODEL,
        timeout: float = 5.0,
    ) -> None:
        self.client = client
        self.model = model
        self.timeout = timeout

    async def triage(self, context: ToolCallContext) -> Optional[SemanticTriageResult]:
        if not self.client or not (
            hasattr(self.client, "models")
            or (hasattr(self.client, "aio") and hasattr(self.client.aio, "models"))
        ):
            return None
        try:
            from google.genai import types

            thinking_lvl = get_gemini_thinking_level(
                task_type="rapid_triage", default="minimal"
            )
            config = types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=SemanticTriageEvaluation,
                thinking_config=(
                    types.ThinkingConfig(thinking_level=thinking_lvl)
                    if thinking_lvl
                    else None
                ),
            )
            prompt = (
                "Analyze this tool execution for malicious intent, unauthorized actions, "
                "privilege escalation, or sensitive data exfiltration.\n"
                f"Tool: {context.tool_name}\n"
                f"Arguments: {context.arguments}\n"
                f"Metadata: {context.metadata or {}}\n"
            )
            timeout = get_gemini_http_timeout(
                configured=self.timeout, task_type="rapid_triage"
            )
            aio_models = getattr(getattr(self.client, "aio", None), "models", None)
            aio_gen = getattr(aio_models, "generate_content", None)
            if aio_gen is not None and inspect.iscoroutinefunction(aio_gen):
                coro = aio_gen(
                    model=self.model,
                    contents=prompt,
                    config=config,
                )
            else:
                coro = asyncio.to_thread(
                    self.client.models.generate_content,
                    model=self.model,
                    contents=prompt,
                    config=config,
                )
            response = await asyncio.wait_for(coro, timeout=timeout)

            # 1. Parsed Pydantic model
            if hasattr(response, "parsed") and response.parsed is not None:
                parsed = response.parsed
                if isinstance(parsed, SemanticTriageEvaluation):
                    return SemanticTriageResult(
                        threat_score=float(parsed.threat_score), backend=self.name
                    )
                if isinstance(parsed, dict) and "threat_score" in parsed:
                    return SemanticTriageResult(
                        threat_score=float(parsed["threat_score"]), backend=self.name
                    )
                if hasattr(parsed, "threat_score"):
                    try:
                        return SemanticTriageResult(
                            threat_score=float(parsed.threat_score), backend=self.name
                        )
                    except (TypeError, ValueError):
                        pass

            # 2. Text JSON parsing
            text = getattr(response, "text", None)
            if text:
                try:
                    data = json.loads(text)
                    if isinstance(data, dict) and "threat_score" in data:
                        return SemanticTriageResult(
                            threat_score=float(data["threat_score"]), backend=self.name
                        )
                except Exception:
                    pass

            return None
        except Exception as exc:
            logger.debug("Semantic intent evaluation fell back to heuristics: %s", exc)
            return None


SEMANTIC_TRIAGE_BACKENDS: Dict[str, Callable[[Any], SemanticTriageProvider]] = {
    GeminiTriageBackend.name: lambda client: GeminiTriageBackend(client)
}


def resolve_semantic_backend(raw: Optional[str]) -> str:
    """Map a configured backend name onto a shipped provider name.

    Defaults to ``gemini`` — the Jev default flip is TASK-D04, not this seam.
    """
    name = normalize_text(raw)
    if not name or name in SEMANTIC_TRIAGE_BACKENDS:
        return name or DEFAULT_SEMANTIC_BACKEND
    if name in PENDING_SEMANTIC_BACKENDS:
        logger.warning(
            "Semantic triage backend %r is specified by FR-01 but is not "
            "implemented until TASK-B01 (.kiro/specs/tier-1-jev-addition/) — "
            "degrading to %r.",
            name,
            DEFAULT_SEMANTIC_BACKEND,
        )
    else:
        logger.warning(
            "unknown semantic triage backend %r — degrading to %r",
            name,
            DEFAULT_SEMANTIC_BACKEND,
        )
    return DEFAULT_SEMANTIC_BACKEND


def build_semantic_provider(
    client: Any, backend: Optional[str] = None
) -> SemanticTriageProvider:
    """Instantiate the provider for ``backend`` (defaults to the shipped one)."""
    name = resolve_semantic_backend(backend)
    return SEMANTIC_TRIAGE_BACKENDS[name](client)

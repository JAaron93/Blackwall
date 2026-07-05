import logging
import json
import re
from typing import Any, Dict, List, Optional

from blackwall.models import ToolCallContext, VerdictDecision, GTIResponse, IndicatorType
from blackwall.policy.models import GateResult
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.mcp.gti_client import GTIMCPClient, GTIDegradedError
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
    ) -> None:
        self.repo = repo
        self.gti_client = gti_client
        self.cbm_client = cbm_client

    async def evaluate(self, context: ToolCallContext, environment_role: str) -> GateResult:
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
        gti_responses = []
        gti_degraded = False
        gti_error = False

        if self.gti_client:
            try:
                for ip in iocs["ips"]:
                    resp = await self.gti_client.queryIOC(ip, IndicatorType.IP_ADDRESS)
                    gti_responses.append(resp)
                for url in iocs["urls"]:
                    resp = await self.gti_client.queryIOC(url, IndicatorType.URL)
                    gti_responses.append(resp)
                for domain in iocs["domains"]:
                    if not any(domain in u for u in iocs["urls"]):
                        resp = await self.gti_client.queryIOC(domain, IndicatorType.DOMAIN)
                        gti_responses.append(resp)
                for h in iocs["hashes"]:
                    resp = await self.gti_client.queryIOC(h, IndicatorType.FILE_HASH)
                    gti_responses.append(resp)
            except GTIDegradedError:
                gti_degraded = True
            except Exception as e:
                logger.error("Error querying GTI MCP: %s", e)
                gti_error = True

        gti_penalty = 0.3 if gti_degraded else 0.0

        # Calculate GTI Score
        gti_score: Optional[float] = None
        if self.gti_client and not gti_degraded and not gti_error:
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
                gti_score = max(scores)

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
                cbm_error = True

        # 4. Context Score
        # Tool risk
        tool_risk = 0.2
        if context.tool_name == "run_command":
            tool_risk = 1.0
        elif context.tool_name in ("write_to_file", "multi_replace_file_content", "replace_file_content", "git"):
            tool_risk = 0.7

        # Argument novelty / suspicious patterns
        args_str = json.dumps(context.arguments)
        # Note: heuristic substrings for detecting suspicious content, not actual secrets/credentials.
        # GitGuardian false-positive suppressed via .gitguardian.yaml
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
    ) -> float:
        """
        Computes the final threat score by aggregating available signals.
        """
        signals = {
            "gti": gti_score,
            "cbm": cbm_score,
            "context": context_score,
        }

        base_weights = {
            "gti": 0.4,
            "cbm": 0.3,
            "context": 0.3,
        }

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

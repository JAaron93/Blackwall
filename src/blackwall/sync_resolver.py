"""
sync_resolver.py — Free-tier single-request synchronous resolver.

Uses client.models.generate_content() (NOT interactions.create()).
No InterceptionQueue, no BatchResolver, no webhooks.
Rate limited to 15 RPM via a token bucket (capacity=15, refill=0.25/s).

Verdict thresholds (DEMO MODE - tuned for standalone testing):
  >= 0.20  → BLOCK
  >= 0.10  → QUARANTINE
  <  0.10  → ALLOW
"""

import asyncio
import logging
import time
from typing import Any, Dict, Optional

from blackwall.models import (
    CBMResponse,
    GTIResponse,
    SyncResolverMetrics,
    ToolCallContext,
    Verdict,
    VerdictDecision,
)
from blackwall.resolver import ContextHygiene, TokenBucketRateLimiter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# High-risk tool names and keywords used in context signal scoring
# ---------------------------------------------------------------------------

_HIGH_RISK_TOOLS = frozenset({
    "execute_shell",
    "execute_bash",
    "execute_terminal",
    "run_command",
    "subprocess",
    "eval",
    "exec",
    "os_exec",
})

_MEDIUM_RISK_TOOLS = frozenset({
    "read_file",
    "write_file",
    "file_write",
    "save_file",
    "query_db",
    "database_query",
    "http_request",
    "socket_connect",
})

_SUSPICIOUS_KEYWORDS = frozenset({
    "passwd",
    "shadow",
    "etc",
    "reverse",
    "shell",
    "payload",
    "inject",
    "exploit",
    "backdoor",
    "exfil",
    "beacon",
    "c2",
    "wget",
    "curl",
    "bash",
    "nc",
    "netcat",
    "chmod",
    "chown",
    "sudo",
    "base64",
    "obfuscat",
    "eval(",
    "exec(",
    "union",
    "select",
    "drop",
    "truncate",
    "insert",
    "delete",
    "xp_cmd",
    "cmdshell",
})


class SyncResolver:
    """
    Free-tier single-request synchronous resolver using
    client.models.generate_content().

    No InterceptionQueue, no BatchResolver, no webhooks.
    Rate limited to 15 RPM via a token bucket.
    """

    def __init__(
        self,
        client: Any,
        policy_server: Any = None,
        repo: Any = None,
        gti_client: Any = None,
        cbm_client: Any = None,
        gti_budget_tracker: Any = None,
        demo_mode: bool = False,
    ) -> None:
        self.client = client
        self.policy_server = policy_server
        self.repo = repo
        self.gti_client = gti_client
        self.cbm_client = cbm_client
        self.gti_budget_tracker = gti_budget_tracker
        self.demo_mode = demo_mode

        # Rate limiter: 15 RPM  →  capacity=15, refill_rate=15/60=0.25 t/s
        self._rate_limiter = TokenBucketRateLimiter(
            capacity=15.0, refill_rate=0.25
        )

        # Context hygiene sanitizer
        self._hygiene = ContextHygiene()

        # True only when the GTI budget tracker explicitly denied the last query.
        # Reset to False at the start of each evaluate() call so the flag is
        # per-interception, not sticky across requests.
        self._gti_budget_exhausted: bool = False

        # Metrics counters
        self._total_evaluations: int = 0
        self._total_latency_ms: float = 0.0
        self._rate_limit_hits: int = 0
        self._gti_queries_executed: int = 0
        self._gti_queries_deferred: int = 0
        self._inline_signatures_generated: int = 0
        self._block_count: int = 0
        self._quarantine_count: int = 0
        self._allow_count: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate(self, context: ToolCallContext) -> Verdict:
        """
        Single-request evaluation.
        Rate-checked → hygiene-sanitized → GTI query → CBM query →
        score aggregation → threshold decision → (optional) inline sig.
        """
        t0 = time.time()

        # Reset per-request GTI budget flag before any queries.
        self._gti_budget_exhausted = False

        # 1. Rate-limit check (fail-closed: QUARANTINE on exhaustion)
        allowed = await self._rate_limiter.consume(1.0)
        if not allowed:
            self._rate_limit_hits += 1
            self._quarantine_count += 1
            self._total_evaluations += 1
            elapsed = (time.time() - t0) * 1000.0
            self._total_latency_ms += elapsed
            return Verdict(
                decision=VerdictDecision.QUARANTINE,
                reasoning=(
                    "Rate limit exhausted (15 RPM). "
                    "Fail-closed: QUARANTINE pending retry."
                ),
                confidence_score=1.0,
            )

        # 2. Sanitize context
        sanitized = self._hygiene.sanitize_context(context)

        # 2b. Check Threat Signature Graph (TSG) for similar attack patterns
        if self.repo:
            matched_sig = await self.repo.find_matching_signature(
                sanitized.tool_name, sanitized.arguments
            )
            if matched_sig:
                self._block_count += 1
                self._total_evaluations += 1
                elapsed = (time.time() - t0) * 1000.0
                self._total_latency_ms += elapsed
                return Verdict(
                    decision=VerdictDecision.BLOCK,
                    reasoning=f"Blocked via signature match: {dict(matched_sig).get('attacker_intent', 'Unknown')}",
                    confidence_score=1.0,
                )

        # 3. Query structural policy and Codebase Memory first (gating before external query)
        cbm_resp: Optional[CBMResponse] = await self._query_cbm(sanitized)

        # 3b. Classify event as high-risk based on structural/CBM signals
        ctx_score = self._score_context(sanitized)
        cbm_score = self._score_cbm(cbm_resp)
        preliminary_score = (cbm_score * 0.50 + ctx_score * 0.50)
        is_high_risk = preliminary_score >= 0.30  # High-risk threshold for GTI gating

        # 4. Query GTI only for high-risk events
        gti_resp: Optional[GTIResponse] = None
        if is_high_risk:
            gti_resp = await self._query_gti(sanitized)

        # 5. Compute weighted threat score
        score = await self._compute_threat_score(sanitized, gti_resp, cbm_resp)
        score = max(0.0, min(1.0, score))

        # 5. Apply verdict thresholds
        if self.demo_mode:
            if score >= 0.20:
                decision = VerdictDecision.BLOCK
            elif score >= 0.10:
                decision = VerdictDecision.QUARANTINE
            else:
                decision = VerdictDecision.ALLOW
        else:
            if score >= 0.75:
                decision = VerdictDecision.BLOCK
            elif score >= 0.50:
                decision = VerdictDecision.QUARANTINE
            else:
                decision = VerdictDecision.ALLOW

        verdict = Verdict(
            decision=decision,
            reasoning=self._build_reasoning(score, gti_resp, cbm_resp),
            confidence_score=score,
        )

        # 6. Inline signature generation after BLOCK
        if decision == VerdictDecision.BLOCK:
            self._block_count += 1
            await self._inline_generate_signature(sanitized, verdict)
        elif decision == VerdictDecision.QUARANTINE:
            self._quarantine_count += 1
        else:
            self._allow_count += 1

        # 7. Metrics
        self._total_evaluations += 1
        elapsed = (time.time() - t0) * 1000.0
        self._total_latency_ms += elapsed

        return verdict

    # ------------------------------------------------------------------
    # GTI query
    # ------------------------------------------------------------------

    async def _query_gti(
        self, context: ToolCallContext
    ) -> Optional[GTIResponse]:
        """
        Query GTI MCP serially (not parallel). Respects GTI budget tracker.
        Returns None if no gti_client, budget exhausted, or query fails.
        """
        if self.gti_client is None:
            return None

        # Budget check
        if self.gti_budget_tracker is not None:
            acquired = self.gti_budget_tracker.tryAcquire()
            if not acquired:
                self._gti_queries_deferred += 1
                self._gti_budget_exhausted = True
                logger.debug(
                    "GTI budget exhausted — deferring query for tool %s",
                    context.tool_name,
                )
                return None

        try:
            # Extract a query indicator from arguments
            indicator = self._extract_indicator(context)
            if not indicator:
                self._gti_queries_deferred += 1
                return None

            result: GTIResponse = await self.gti_client.query(indicator)
            self._gti_queries_executed += 1
            return result

        except Exception as exc:
            logger.warning(
                "GTI query failed — continuing without GTI signal: %s", exc,
            )
            self._gti_queries_deferred += 1
            return None

    # ------------------------------------------------------------------
    # CBM query
    # ------------------------------------------------------------------

    async def _query_cbm(
        self, context: ToolCallContext
    ) -> Optional[CBMResponse]:
        """
        Query CBM MCP serially (not parallel).
        Returns None if no cbm_client or query fails.
        """
        if self.cbm_client is None:
            return None

        try:
            result: CBMResponse = await self.cbm_client.query(context)
            return result

        except Exception as exc:
            logger.warning(
                "CBM query failed — continuing without CBM signal: %s", exc,
            )
            return None

    # ------------------------------------------------------------------
    # Threat score computation
    # ------------------------------------------------------------------

    async def _compute_threat_score(
        self,
        context: ToolCallContext,
        gti_resp: Optional[GTIResponse],
        cbm_resp: Optional[CBMResponse],
    ) -> float:
        """
        Weighted aggregation: GTI 40% + CBM 30% + Context 30%.

        The −0.20 penalty and weight redistribution (CBM 50% + Context 50%)
        only applies when the GTI budget tracker explicitly denied the query
        (self._gti_budget_exhausted is True).  Other reasons for gti_resp
        being None — GTI not configured, no extractable indicator, or a
        transient query failure — use normal weights with gti_score = 0.0,
        which is already the correct fallback from _score_gti(None).
        """
        gti_score = self._score_gti(gti_resp)
        cbm_score = self._score_cbm(cbm_resp)
        ctx_score = self._score_context(context)

        if self._gti_budget_exhausted:
            # Budget depletion: apply spec-mandated weight redistribution
            # and −0.2 penalty to reflect reduced detection confidence.
            score = (
                cbm_score * 0.50
                + ctx_score * 0.50
                - 0.20
            )
        else:
            # Normal path: GTI 40% + CBM 30% + Context 30%.
            # When gti_resp is None for any other reason, gti_score is 0.0,
            # which naturally reduces the GTI contribution without a penalty.
            score = (
                gti_score * 0.40
                + cbm_score * 0.30
                + ctx_score * 0.30
            )

        return score

    # ------------------------------------------------------------------
    # Inline signature generation (BLOCK path)
    # ------------------------------------------------------------------

    async def _inline_generate_signature(
        self, context: ToolCallContext, verdict: Verdict
    ) -> None:
        """
        After BLOCK: generate a threat signature inline using
        generate_content() and write it to the SQLite repo.
        Adds ~200-500ms. Skipped gracefully if repo is None or Gemini fails.
        """
        try:
            prompt = (
                "Generalize this attack pattern into a reusable threat signature.\n"
                f"Tool: {context.tool_name}\n"
                f"Arguments: {context.arguments}\n"
                f"Verdict reasoning: {verdict.reasoning}\n"
                "Respond with a concise signature description "
                "(attacker_intent, payload_pattern, target_sink)."
            )

            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self.client.models.generate_content,
                    model="gemini-2.0-flash-lite",
                    contents=prompt,
                ),
                timeout=30.0,
            )
            sig_text = (
                response.text
                if hasattr(response, "text")
                else str(response)
            )

            if self.repo is not None:
                await self.repo.writeSignature(
                    {
                        "attackerIntent": (
                            f"Blocked tool call: {context.tool_name}"
                        ),
                        "payloadPattern": sig_text[:512],
                        "targetTool": context.tool_name,
                        "mitigationAction": "BLOCK",
                        "metadata": {
                            "confidence_score": verdict.confidence_score,
                        },
                    }
                )

            self._inline_signatures_generated += 1

        except Exception as exc:
            logger.warning(
                "Inline signature generation failed — skipping: %s", exc,
            )

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def get_metrics(self) -> dict:
        """Returns a SyncResolverMetrics dataclass as a dict."""
        avg_latency = (
            self._total_latency_ms / self._total_evaluations
            if self._total_evaluations > 0
            else 0.0
        )
        return SyncResolverMetrics(
            total_evaluations=self._total_evaluations,
            average_latency_ms=avg_latency,
            rate_limit_hits=self._rate_limit_hits,
            gti_queries_executed=self._gti_queries_executed,
            gti_queries_deferred=self._gti_queries_deferred,
            inline_signatures_generated=self._inline_signatures_generated,
            block_count=self._block_count,
            quarantine_count=self._quarantine_count,
            allow_count=self._allow_count,
        ).model_dump()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _score_gti(self, gti_resp: Optional[GTIResponse]) -> float:
        """
        GTI signal (0.0–1.0).
          is_malicious=True  → 1.0
          detection_rate     → fractional score
          Both available     → average of is_malicious score and detection_rate
        """
        if gti_resp is None:
            return 0.0

        malicious_score = 1.0 if gti_resp.is_malicious else 0.0
        detection_score = max(0.0, min(1.0, gti_resp.detection_rate))

        if gti_resp.is_malicious:
            # Both components available: average them
            return (malicious_score + detection_score) / 2.0
        # Only detection_rate contributes when not flagged malicious
        return detection_score

    def _score_cbm(self, cbm_resp: Optional[CBMResponse]) -> float:
        """
        CBM signal (0.0–1.0).
          blast_radius normalised: min(blast_radius / 10, 1.0)
          critical sinks: each sink type adds 0.1 (cap 0.5)
          Combined as average of the two components.
        """
        if cbm_resp is None:
            return 0.0

        blast_score = min(cbm_resp.blast_radius / 10.0, 1.0)
        sink_score = min(len(cbm_resp.critical_sinks) * 0.1, 0.5)
        return (blast_score + sink_score) / 2.0

    def _score_context(self, context: ToolCallContext) -> float:
        """
        Context signal (0.0–1.0) based on:
          - Tool name risk level
          - Argument novelty (suspicious keyword count)
          - Environment role (from metadata)
        """
        tool_score = self._score_tool_name(context.tool_name)
        novelty_score = self._score_argument_novelty(context.arguments)

        # Environment role modifier
        role_modifier = 0.0
        if context.metadata:
            role = context.metadata.get("environment_role", "").lower()
            if role in ("production", "prod"):
                role_modifier = 0.15
            elif role in ("staging",):
                role_modifier = 0.05

        raw = (tool_score * 0.50 + novelty_score * 0.50) + role_modifier
        return max(0.0, min(1.0, raw))

    def _score_tool_name(self, tool_name: str) -> float:
        """Returns scoring for tool name based on risk level."""
        name_lower = tool_name.lower()
        if self.demo_mode:
            for risky in _HIGH_RISK_TOOLS:
                if risky in name_lower:
                    return 1.0
            for medium in _MEDIUM_RISK_TOOLS:
                if medium in name_lower:
                    return 0.6
            return 0.15
        else:
            for risky in _HIGH_RISK_TOOLS:
                if risky in name_lower:
                    return 0.9
            for medium in _MEDIUM_RISK_TOOLS:
                if medium in name_lower:
                    return 0.45
            return 0.1

    def _score_argument_novelty(
        self, arguments: Dict[str, Any]
    ) -> float:
        """Counts suspicious keywords found in stringified argument values."""
        combined = " ".join(str(v) for v in arguments.values()).lower()
        count = sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw in combined)
        if self.demo_mode:
            return min(count * 0.25, 1.0)  # Boosted from 0.2
        else:
            return min(count * 0.2, 1.0)  # Specification-mandated multiplier

    def _extract_indicator(self, context: ToolCallContext) -> Optional[str]:
        """Extracts the most useful GTI indicator from the context arguments."""
        args_str = " ".join(str(v) for v in context.arguments.values())
        import re

        # Try to find IP addresses
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", args_str)
        if ip_match:
            return ip_match.group(0)

        # Try to extract domain from URLs
        url_match = re.search(r"https?://([^\s/:]+)", args_str)
        if url_match:
            domain = url_match.group(1)
            # Skip localhost and private domains
            if domain not in ("localhost", "127.0.0.1") and not domain.startswith("192.168."):
                return domain

        # Look for standalone domain patterns
        domain_match = re.search(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", args_str, re.IGNORECASE)
        if domain_match:
            return domain_match.group(0)

        return None

    @staticmethod
    def _build_reasoning(
        score: float,
        gti_resp: Optional[GTIResponse],
        cbm_resp: Optional[CBMResponse],
    ) -> str:
        parts = [f"Threat score: {score:.3f}"]
        if gti_resp is not None:
            parts.append(
                f"GTI: malicious={gti_resp.is_malicious}, "
                f"detection_rate={gti_resp.detection_rate:.2f}"
            )
        if cbm_resp is not None:
            parts.append(
                f"CBM: blast_radius={cbm_resp.blast_radius}, "
                f"sinks={len(cbm_resp.critical_sinks)}"
            )
        return " | ".join(parts)

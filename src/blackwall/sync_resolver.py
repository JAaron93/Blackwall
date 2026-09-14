"""
sync_resolver.py — Synchronous single-request resolver (100% GCP Vertex AI 300 RPM Mode).

Uses client.models.generate_content() (NOT interactions.create()).
Single-request synchronous evaluation resolver for inline tool-call gating.
Rate limited to 300 RPM via a token bucket (capacity=300, refill=5.0/s) under 100% GCP Vertex AI Mode.
Performs ContextHygiene sanitization, Threat Signature Graph lookup,
CBM AST query, GTI external threat intelligence check, optional Gemini 3.5 Flash-Lite
semantic triage, threat score aggregation, and threshold-based verdict dispatch.

Verdict thresholds (DEMO MODE - tuned for standalone testing):
  >= 0.20  → BLOCK
  >= 0.10  → QUARANTINE
  <  0.10  → ALLOW
"""

import asyncio
import concurrent.futures
from datetime import datetime, timezone
import json
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from blackwall.analytics import AgentBehavioralAnalytics
from blackwall.attribution import (
    AttackerIdentityExtractor,
    IncidentReportGenerator,
)
from blackwall.config import (
    DEFAULT_RAPID_TRIAGE_MODEL,
    get_gemini_http_timeout,
    get_gemini_thinking_level,
)
from blackwall.models import (
    AttackerProfile,
    CBMResponse,
    EventType,
    GTIResponse,
    IncidentReport,
    RefactoringHint,
    SecurityEvent,
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

_HIGH_RISK_TOOLS = frozenset(
    {
        "execute_shell",
        "execute_bash",
        "execute_terminal",
        "run_command",
        "subprocess",
        "eval",
        "exec",
        "os_exec",
    }
)

_MEDIUM_RISK_TOOLS = frozenset(
    {
        "read_file",
        "write_file",
        "file_write",
        "save_file",
        "query_db",
        "database_query",
        "http_request",
        "socket_connect",
    }
)

_SUSPICIOUS_KEYWORDS = frozenset(
    {
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
        "rm -rf",
        "system(",
        "popen",
        "import os",
        "import sys",
        "import socket",
    }
)


class SemanticTriageEvaluation(BaseModel):
    threat_score: float = Field(..., ge=0.0, le=1.0, description="Risk assessment score between 0.0 and 1.0")
    is_suspicious: bool = Field(..., description="Whether the tool call exhibits malicious intent")
    reasoning: str = Field(..., description="Concise rationale for the verdict")


class ThreatSignaturePayload(BaseModel):
    attacker_intent: str = Field(..., description="Concise description of the attacker's intent")
    payload_pattern: str = Field(..., description="General payload or attack pattern")
    target_sink: str = Field(default="", description="Target sink or tool")
    mitigation_action: str = Field(default="BLOCK", description="Recommended mitigation action")


class SyncResolver:
    """
    Synchronous single-request resolver for Blackwall Core (300 RPM Vertex AI Mode).

    Performs interception, evaluation, self-learning threat signature creation,
    and non-blocking attacker attribution (<5ms SLA, NFR-1 & NFR-2).
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
        on_attacker_identified: Optional[Callable[[IncidentReport], Any]] = None,
        telemetry: Optional[Any] = None,
        enable_semantic_triage: Optional[bool] = None,
        aba: Optional[Any] = None,
    ) -> None:
        self.client = client
        self.policy_server = policy_server
        self.repo = repo
        self.gti_client = gti_client
        self.cbm_client = cbm_client
        self.gti_budget_tracker = gti_budget_tracker
        self.demo_mode = demo_mode
        self.on_attacker_identified = on_attacker_identified
        self.telemetry = telemetry
        self.aba = aba or AgentBehavioralAnalytics(
            repo=self.repo,
            client=self.client,
        )

        if enable_semantic_triage is None:
            self.enable_semantic_triage = (
                os.getenv("BLACKWALL_ENABLE_SYNC_SEMANTIC_TRIAGE", "").strip().lower()
                in ("true", "1", "yes")
            )
        else:
            self.enable_semantic_triage = bool(enable_semantic_triage)

        # Wire MCP client URLs from policy server if configured
        policy = getattr(
            getattr(self.policy_server, "structural_engine", None), "_policy", None
        )
        if policy and hasattr(policy, "mcpServers"):
            mcp = policy.mcpServers
            if (
                getattr(mcp, "gti", None)
                and getattr(mcp.gti, "url", None)
                and self.gti_client
            ):
                if hasattr(self.gti_client, "base_url"):
                    self.gti_client.base_url = mcp.gti.url
            if (
                getattr(mcp, "codebaseMemory", None)
                and getattr(mcp.codebaseMemory, "url", None)
                and self.cbm_client
            ):
                if hasattr(self.cbm_client, "base_url"):
                    self.cbm_client.base_url = mcp.codebaseMemory.url

        # Background tasks set & callback executor pool for non-blocking lifecycle management
        self._background_tasks: set[asyncio.Task[Any]] = set()
        self._callback_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="bw_callback"
        )

        # Rate limiter: 100% GCP Vertex AI Mode (Paid Tier Exclusively: 300 RPM capacity, 5.0 t/s refill)
        self._rate_limiter = TokenBucketRateLimiter(
            capacity=300.0, refill_rate=5.0
        )

        # Context hygiene sanitizer with security IOC preservation mode enabled
        self._hygiene = ContextHygiene(preserve_iocs=True)

        # True only when the GTI budget tracker explicitly denied the last query.
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
        Must complete in < 5ms (SLA).
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
                    "Rate limit exhausted (300 RPM). "
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
                verdict = Verdict(
                    decision=VerdictDecision.BLOCK,
                    reasoning=f"Blocked via signature match: {dict(matched_sig).get('attacker_intent', 'Unknown')}",
                    confidence_score=1.0,
                )
                self._schedule_attribution(context, verdict)
                return verdict

        # 3. Query structural policy and Codebase Memory first (gating before external query)
        cbm_resp: Optional[CBMResponse] = await self._query_cbm(sanitized)

        # 3b. Classify event as high-risk based on structural/CBM signals
        ctx_score = self._score_context(sanitized)
        cbm_score = self._score_cbm(cbm_resp)
        preliminary_score = cbm_score * 0.50 + ctx_score * 0.50
        is_high_risk = preliminary_score >= 0.30  # High-risk threshold for GTI gating

        # 4. Query GTI only for high-risk events
        gti_resp: Optional[GTIResponse] = None
        if is_high_risk:
            gti_resp = await self._query_gti(sanitized)

        # 4b. Optional semantic triage via Gemini 3.5 Flash-Lite
        semantic_score: Optional[float] = None
        if self.enable_semantic_triage and self.client is not None:
            semantic_score = await self._evaluate_semantic_intent(sanitized)

        # 5. Compute weighted threat score
        score = await self._compute_threat_score(
            sanitized, gti_resp, cbm_resp, semantic_score=semantic_score
        )
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
            reasoning=self._build_reasoning(
                score, gti_resp, cbm_resp, semantic_score=semantic_score
            ),
            confidence_score=score,
        )

        # 6. Non-blocking Attacker Attribution post-verdict
        if decision in (VerdictDecision.BLOCK, VerdictDecision.QUARANTINE):
            self._schedule_attribution(context, verdict)

        if decision == VerdictDecision.BLOCK:
            self._block_count += 1
            await self._inline_generate_signature(
                sanitized, verdict, gti_resp=gti_resp, cbm_resp=cbm_resp
            )
        elif decision == VerdictDecision.QUARANTINE:
            self._quarantine_count += 1
            await self._handle_quarantine_refactoring(
                sanitized, verdict, gti_resp=gti_resp, cbm_resp=cbm_resp
            )
        else:
            self._allow_count += 1

        # 7. Metrics
        self._total_evaluations += 1
        elapsed = (time.time() - t0) * 1000.0
        self._total_latency_ms += elapsed

        return verdict

    def _schedule_attribution(self, context: ToolCallContext, verdict: Verdict) -> None:
        """Schedules attacker attribution non-blockingly in a background task to preserve verdict SLA (<5ms)."""
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(self._process_attribution(context, verdict))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        except RuntimeError:
            pass

    async def flush_background_tasks(self) -> None:
        """Awaits all pending background attribution tasks to complete."""
        if self._background_tasks:
            await asyncio.gather(*list(self._background_tasks), return_exceptions=True)

    async def close(self) -> None:
        """Flushes background tasks and shuts down executor pools."""
        await self.flush_background_tasks()
        self._callback_executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------
    # Attacker Attribution processing
    # ------------------------------------------------------------------

    async def _process_attribution(
        self,
        context: ToolCallContext,
        verdict: Verdict,
    ) -> None:
        """
        Extract identity from sanitized context/metadata, update profile DB,
        generate incident report with sanitized arguments, and emit notification sinks.
        Enforces fail-safe exception isolation (<5ms budget, NFR-2).
        """
        try:
            sanitized = self._hygiene.sanitize_context(context)
            extractor = AttackerIdentityExtractor()
            identity = extractor.extract(context=sanitized, metadata=sanitized.metadata)

            now_utc = datetime.now(timezone.utc)
            initial_profile = AttackerProfile(
                fingerprint=identity.identity_fingerprint,
                first_seen=now_utc,
                last_seen=now_utc,
                total_attacks=1,
                threat_score=verdict.confidence_score,
                targeted_tools=[context.tool_name],
            )

            if self.repo and hasattr(self.repo, "upsert_attacker_profile"):
                profile = await self.repo.upsert_attacker_profile(initial_profile)
            else:
                profile = initial_profile

            generator = IncidentReportGenerator()
            report = generator.build(
                event_id=uuid4(),
                verdict=verdict.decision,
                identity=identity,
                profile=profile,
                tool_context=sanitized,
                technique="Intercepted Unsafe Tool Execution",
                mitigation=verdict.reasoning,
                recommended_action="Revoke agent credentials and inspect execution trace",
                confidence=verdict.confidence_score,
            )

            # Emit notification sinks with non-blocking error isolation
            await self._emit_sinks(report, identity, profile)

        except Exception as exc:
            logger.warning(
                "Attacker attribution failed gracefully (fail-safe mode): %s", exc
            )

    async def _emit_sinks(
        self, report: IncidentReport, identity: Any, profile: AttackerProfile
    ) -> None:
        """Emits notification sinks (CLI stderr, user callback, telemetry) with isolated error handling."""
        # 1. Output to CLI sink (stderr)
        try:
            sys.stderr.write(report.to_markdown() + "\n")
            sys.stderr.flush()
        except Exception as err:
            logger.warning("CLI alert sink output failed: %s", err)

        # 2. Execute user callback if registered (non-blocking executor pool with timeout, isolated)
        if self.on_attacker_identified is not None:
            try:
                if asyncio.iscoroutinefunction(self.on_attacker_identified):
                    await asyncio.wait_for(
                        self.on_attacker_identified(report), timeout=0.05
                    )
                else:
                    loop = asyncio.get_running_loop()
                    await asyncio.wait_for(
                        loop.run_in_executor(
                            self._callback_executor, self.on_attacker_identified, report
                        ),
                        timeout=0.05,
                    )
            except Exception as err:
                logger.warning("Attacker identified callback failed: %s", err)

        # 3. Emit OpenTelemetry security event span if telemetry enabled (isolated)
        if self.telemetry and hasattr(self.telemetry, "create_span"):
            try:
                span_name = "blackwall.attacker_identified"
                attrs = {
                    "attacker.agent_id": identity.agent_id or "UNKNOWN",
                    "attacker.agent_name": identity.agent_name or "UNKNOWN",
                    "attacker.fingerprint": identity.identity_fingerprint,
                    "attacker.score": profile.threat_score,
                    "attacker.total_attacks": profile.total_attacks,
                }
                self.telemetry.create_span(span_name, attributes=attrs)
            except Exception as err:
                logger.warning("OpenTelemetry span emission failed: %s", err)

    # ------------------------------------------------------------------
    # GTI query
    # ------------------------------------------------------------------

    async def _query_gti(self, context: ToolCallContext) -> Optional[GTIResponse]:
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
                "GTI query failed — continuing without GTI signal: %s",
                exc,
            )
            self._gti_queries_deferred += 1
            return None

    # ------------------------------------------------------------------
    # CBM query
    # ------------------------------------------------------------------

    async def _query_cbm(self, context: ToolCallContext) -> Optional[CBMResponse]:
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
                "CBM query failed — continuing without CBM signal: %s",
                exc,
            )
            return None

    # ------------------------------------------------------------------
    # Threat score computation & semantic intent evaluation
    # ------------------------------------------------------------------

    async def _evaluate_semantic_intent(
        self, context: ToolCallContext
    ) -> Optional[float]:
        """
        Evaluate tool execution intent semantically using Gemini 3.5 Flash-Lite.
        Enforces thinking_level='minimal' for rapid latency (<50ms).
        Falls back gracefully to None on timeout, missing client, or failure.
        """
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
                thinking_config=types.ThinkingConfig(thinking_level=thinking_lvl)
                if thinking_lvl
                else None,
            )
            prompt = (
                "Analyze this tool execution for malicious intent, unauthorized actions, "
                "privilege escalation, or sensitive data exfiltration.\n"
                f"Tool: {context.tool_name}\n"
                f"Arguments: {context.arguments}\n"
                f"Metadata: {context.metadata or {}}\n"
            )
            timeout = get_gemini_http_timeout(configured=5.0, task_type="rapid_triage")
            aio_models = getattr(getattr(self.client, "aio", None), "models", None)
            aio_gen = getattr(aio_models, "generate_content", None)
            if aio_gen is not None and asyncio.iscoroutinefunction(aio_gen):
                coro = aio_gen(
                    model=DEFAULT_RAPID_TRIAGE_MODEL,
                    contents=prompt,
                    config=config,
                )
            else:
                coro = asyncio.to_thread(
                    self.client.models.generate_content,
                    model=DEFAULT_RAPID_TRIAGE_MODEL,
                    contents=prompt,
                    config=config,
                )
            response = await asyncio.wait_for(coro, timeout=timeout)

            # 1. Parsed Pydantic model
            if hasattr(response, "parsed") and response.parsed is not None:
                parsed = response.parsed
                if isinstance(parsed, SemanticTriageEvaluation):
                    return float(parsed.threat_score)
                if isinstance(parsed, dict) and "threat_score" in parsed:
                    return float(parsed["threat_score"])
                if hasattr(parsed, "threat_score"):
                    try:
                        return float(parsed.threat_score)
                    except (TypeError, ValueError):
                        pass

            # 2. Text JSON parsing
            text = getattr(response, "text", None)
            if text:
                try:
                    data = json.loads(text)
                    if isinstance(data, dict) and "threat_score" in data:
                        return float(data["threat_score"])
                except Exception:
                    pass

            return None
        except Exception as exc:
            logger.debug("Semantic intent evaluation fell back to heuristics: %s", exc)
            return None

    async def _compute_threat_score(
        self,
        context: ToolCallContext,
        gti_resp: Optional[GTIResponse],
        cbm_resp: Optional[CBMResponse],
        semantic_score: Optional[float] = None,
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

        if (
            semantic_score is None
            and self.enable_semantic_triage
            and self.client is not None
        ):
            semantic_score = await self._evaluate_semantic_intent(context)

        ctx_score = self._score_context(context, semantic_score=semantic_score)

        if self._gti_budget_exhausted:
            # Budget depletion: apply spec-mandated weight redistribution
            # and −0.2 penalty to reflect reduced detection confidence.
            score = cbm_score * 0.50 + ctx_score * 0.50 - 0.20
        else:
            # Normal path: GTI 40% + CBM 30% + Context 30%.
            # When gti_resp is None for any other reason, gti_score is 0.0,
            # which naturally reduces the GTI contribution without a penalty.
            score = gti_score * 0.40 + cbm_score * 0.30 + ctx_score * 0.30

        return score

    # ------------------------------------------------------------------
    # Inline signature generation (BLOCK path)
    # ------------------------------------------------------------------

    async def _inline_generate_signature(
        self,
        context: ToolCallContext,
        verdict: Verdict,
        gti_resp: Optional[GTIResponse] = None,
        cbm_resp: Optional[CBMResponse] = None,
    ) -> None:
        """
        After BLOCK: generate a threat signature inline using
        ABA.generateSignature() and write it to the SQLite repo.
        Adds ~200-500ms. Skipped gracefully if repo is None or Gemini fails.
        """
        try:
            from google.genai import types

            attacker_intent = f"Blocked tool call: {context.tool_name}"
            payload_pattern = ""
            mitigation_action = "BLOCK"

            # 1. If client has models.generate_content, invoke it to support prompt-based summarization
            if self.client and (
                hasattr(self.client, "models")
                or (hasattr(self.client, "aio") and hasattr(self.client.aio, "models"))
            ):
                thinking_lvl = get_gemini_thinking_level(
                    task_type="signature_generation", default="high"
                )
                config = types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ThreatSignaturePayload,
                    thinking_config=types.ThinkingConfig(thinking_level=thinking_lvl)
                    if thinking_lvl
                    else None,
                )
                prompt = (
                    "Generalize this attack pattern into a reusable threat signature.\n"
                    f"Tool: {context.tool_name}\n"
                    f"Arguments: {context.arguments}\n"
                    f"Verdict reasoning: {verdict.reasoning}\n"
                    "Respond with a concise signature description "
                    "(attacker_intent, payload_pattern, target_sink, mitigation_action)."
                )

                timeout = get_gemini_http_timeout(
                    configured=30.0, task_type="signature_generation"
                )
                aio_models = getattr(getattr(self.client, "aio", None), "models", None)
                aio_gen = getattr(aio_models, "generate_content", None)
                if aio_gen is not None and asyncio.iscoroutinefunction(aio_gen):
                    coro = aio_gen(
                        model=DEFAULT_RAPID_TRIAGE_MODEL,
                        contents=prompt,
                        config=config,
                    )
                else:
                    coro = asyncio.to_thread(
                        self.client.models.generate_content,
                        model=DEFAULT_RAPID_TRIAGE_MODEL,
                        contents=prompt,
                        config=config,
                    )
                response = await asyncio.wait_for(coro, timeout=timeout)

                parsed = getattr(response, "parsed", None)
                if parsed is not None and not type(parsed).__name__.endswith("Mock"):
                    if isinstance(parsed, ThreatSignaturePayload):
                        attacker_intent = parsed.attacker_intent or attacker_intent
                        payload_pattern = parsed.payload_pattern or ""
                        mitigation_action = parsed.mitigation_action or "BLOCK"
                    elif isinstance(parsed, dict):
                        attacker_intent = parsed.get("attacker_intent") or attacker_intent
                        payload_pattern = parsed.get("payload_pattern") or ""
                        mitigation_action = parsed.get("mitigation_action") or "BLOCK"
                    elif hasattr(parsed, "attacker_intent") and hasattr(parsed, "payload_pattern"):
                        attacker_intent = str(getattr(parsed, "attacker_intent", attacker_intent))
                        payload_pattern = str(getattr(parsed, "payload_pattern", ""))
                        mitigation_action = str(getattr(parsed, "mitigation_action", "BLOCK"))

                if not payload_pattern and hasattr(response, "text") and response.text:
                    sig_text = response.text
                    try:
                        data = json.loads(sig_text)
                        if isinstance(data, dict):
                            attacker_intent = data.get("attacker_intent") or attacker_intent
                            payload_pattern = data.get("payload_pattern") or ""
                            mitigation_action = data.get("mitigation_action") or "BLOCK"
                        else:
                            payload_pattern = sig_text[:512]
                    except Exception:
                        payload_pattern = sig_text[:512]
                elif not payload_pattern:
                    payload_pattern = str(response)[:512]

            # 2. Wire ABA.generateSignature() to produce 768-dim embedding and persist to TSG
            ctx_copy = context.model_copy(deep=True)
            if ctx_copy.metadata is None:
                ctx_copy.metadata = {}
            if payload_pattern:
                ctx_copy.metadata["payload_pattern"] = payload_pattern
            if attacker_intent and attacker_intent != f"Blocked tool call: {context.tool_name}":
                ctx_copy.metadata["attacker_intent"] = attacker_intent
            if mitigation_action:
                ctx_copy.metadata["mitigation_action"] = mitigation_action

            sec_event = SecurityEvent(
                event_type=EventType.BLOCK,
                tool_context=ctx_copy,
                verdict=Verdict(
                    decision=verdict.decision,
                    reasoning=attacker_intent,
                    confidence_score=verdict.confidence_score,
                ),
                gti_response=gti_resp,
                cbm_response=cbm_resp,
                agent_id=context.metadata.get("agent_id") if context.metadata else None,
            )

            if self.aba is not None:
                await self.aba.generateSignature(sec_event)
            elif self.repo is not None:
                if not payload_pattern:
                    payload_pattern = str(context.arguments)[:512]
                await self.repo.writeSignature(
                    {
                        "attackerIntent": attacker_intent,
                        "payloadPattern": payload_pattern[:512],
                        "targetTool": context.tool_name,
                        "mitigationAction": mitigation_action,
                        "metadata": {
                            "confidence_score": verdict.confidence_score,
                        },
                    }
                )

            self._inline_signatures_generated += 1

        except Exception as exc:
            logger.warning(
                "Inline signature generation failed — skipping: %s",
                exc,
            )

    async def _handle_quarantine_refactoring(
        self,
        context: ToolCallContext,
        verdict: Verdict,
        gti_resp: Optional[GTIResponse] = None,
        cbm_resp: Optional[CBMResponse] = None,
    ) -> Optional[RefactoringHint]:
        """
        After QUARANTINE: trigger Green Team auto-refactoring via ABA.triggerRefactoring().
        """
        if not self.aba:
            return None
        try:
            sec_event = SecurityEvent(
                event_type=EventType.QUARANTINE,
                tool_context=context,
                verdict=verdict,
                gti_response=gti_resp,
                cbm_response=cbm_resp,
                agent_id=context.metadata.get("agent_id") if context.metadata else None,
            )
            return await self.aba.triggerRefactoring(sec_event)
        except Exception as exc:
            logger.warning("Quarantine refactoring generation failed: %s", exc)
            return None

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

    def _score_context(
        self,
        context: ToolCallContext,
        semantic_score: Optional[float] = None,
    ) -> float:
        """
        Context signal (0.0–1.0) based on:
          - Tool name risk level
          - Argument novelty (suspicious keyword count or semantic intent score)
          - Environment role (from metadata)
        """
        tool_score = self._score_tool_name(context.tool_name)
        novelty_score = self._score_argument_novelty(
            context.arguments, semantic_score=semantic_score
        )

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
        self,
        arguments: Dict[str, Any],
        semantic_score: Optional[float] = None,
    ) -> float:
        """Counts suspicious keywords found in stringified argument values and combines with semantic score (fail-closed max)."""
        combined = " ".join(str(v) for v in arguments.values()).lower()
        count = sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw in combined)
        if self.demo_mode:
            deterministic_novelty = min(count * 0.25, 1.0)  # Boosted from 0.2
        else:
            deterministic_novelty = min(count * 0.2, 1.0)  # Specification-mandated multiplier

        if semantic_score is not None:
            bounded_semantic = max(0.0, min(1.0, float(semantic_score)))
            # Fail-closed: semantic triage must never lower the deterministic risk signal
            return max(deterministic_novelty, bounded_semantic)

        return deterministic_novelty

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
            if domain not in ("localhost", "127.0.0.1") and not domain.startswith(
                "192.168."
            ):
                return domain

        # Look for standalone domain patterns
        domain_match = re.search(
            r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", args_str, re.IGNORECASE
        )
        if domain_match:
            return domain_match.group(0)

        return None

    @staticmethod
    def _build_reasoning(
        score: float,
        gti_resp: Optional[GTIResponse],
        cbm_resp: Optional[CBMResponse],
        semantic_score: Optional[float] = None,
    ) -> str:
        parts = [f"Threat score: {score:.3f}"]
        if semantic_score is not None:
            parts.append(f"Semantic: score={semantic_score:.2f}")
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

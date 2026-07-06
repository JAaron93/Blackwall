import asyncio
import hashlib
import json
import logging
import random
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from blackwall.models import (
    BehaviorScore,
    EventType,
    RefactoringHint,
    SecurityEvent,
    ThreatSignature,
    SinkType,
)
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.mcp.embeddings import GeminiEmbeddingClient

logger = logging.getLogger("blackwall.analytics")

# Optional OpenTelemetry import
try:
    from opentelemetry import trace
    _has_otel = True
except ImportError:
    _has_otel = False

# Optional SentenceTransformers import
try:
    from sentence_transformers import SentenceTransformer
    _has_sentence_transformers = True
except ImportError:
    _has_sentence_transformers = False


class AgentBehavioralAnalytics:
    """
    Runtime monitoring engine tracking behavioral drift, updating AgBOM,
    generating threat signatures, and suggesting refactoring hints.
    """

    def __init__(
        self,
        repo: Optional[SQLiteThreatRepository] = None,
        client: Optional[Any] = None,
        baseline_score: float = 1.0,  # default baseline on 0-5 scale
        allowed_tools: Optional[Set[str]] = None,
        model_name: str = "all-MiniLM-L6-v2",
    ) -> None:
        self.repo = repo
        self.client = client
        self.baseline_score = baseline_score
        self.allowed_tools = allowed_tools
        self.model_name = model_name
        self.agbom: Dict[str, Any] = {"tools": {}}
        self._embedding_model = None
        self.embedding_client = GeminiEmbeddingClient(client) if client is not None else None

        if _has_otel:
            self.tracer = trace.get_tracer("blackwall.analytics")
        else:
            self.tracer = None

    def _get_embedding_model(self) -> Optional[Any]:
        if self._embedding_model is None and _has_sentence_transformers:
            try:
                self._embedding_model = SentenceTransformer(self.model_name)
            except Exception as e:
                logger.warning("Failed to load SentenceTransformer: %s", e)
        return self._embedding_model

    def _get_embedding(self, text: str) -> List[float]:
        model = self._get_embedding_model()
        if model is not None:
            return model.encode(text).tolist()

        # Deterministic fallback embedding generation (768 dimensions)
        seed = int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16) & 0xFFFFFFFF
        rng = random.Random(seed)
        return [rng.uniform(-1.0, 1.0) for _ in range(768)]

    def _generalize_string(self, text: str) -> str:
        # Regex-based generalization of known specific patterns
        # 1. API Keys
        text = re.sub(
            r"(?i)(api[_-]?key|apikey|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})",
            r"\1:[[API_KEY]]",
            text,
        )
        # 2. IP Addresses
        text = re.sub(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "[[IP_ADDRESS]]",
            text,
        )
        # 3. Scripts ending with script extensions (e.g., script.sh, run.py)
        text = re.sub(
            r"\b([a-zA-Z0-9_-]+\.(?:sh|py|pl|bash|rb))\b",
            "[[SCRIPT_NAME]]",
            text,
        )
        # 4. URLs (only if they don't already contain placeholders)
        def url_repl(match: re.Match[str]) -> str:
            url = match.group(0)
            if "[[" in url:
                return url
            return "[[URL]]"
        text = re.sub(r"https?://[^\s\"']+", url_repl, text)

        # 5. Passwords
        text = re.sub(
            r"(?i)(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]+)",
            r"\1:[[PASSWORD]]",
            text,
        )
        # 6. Emails
        text = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "[[EMAIL]]",
            text,
        )
        # 7. Absolute / relative file paths (avoid replacing placeholders)
        text = re.sub(
            r"(?<!\[)(?:/[a-zA-Z0-9_.-]+)+",
            "[[FILE_PATH]]",
            text,
        )
        return text

    def _generalize_dict_value(self, val: Any, key: Optional[str] = None) -> Any:
        if isinstance(val, str):
            if key and any(k in key.lower() for k in ("api_key", "apikey", "token")):
                if len(val) >= 20:
                    return "[[API_KEY]]"
            if key and any(k in key.lower() for k in ("password", "passwd", "pwd")):
                return "[[PASSWORD]]"
            return self._generalize_string(val)
        elif isinstance(val, dict):
            return {k: self._generalize_dict_value(v, k) for k, v in val.items()}
        elif isinstance(val, list):
            return [self._generalize_dict_value(v, key) for v in val]
        return val

    def _generalize_payload(self, arguments: Dict[str, Any]) -> str:
        gen_args = self._generalize_dict_value(arguments)
        try:
            args_str = json.dumps(gen_args)
        except Exception:
            args_str = str(gen_args)
        return args_str

    async def scoreEvent(self, event: SecurityEvent) -> BehaviorScore:
        """
        Calculates behavioral drift using LLM-as-judge on a 0-5 scale.
        Normalizes the score to [0.0, 1.0] for the returned BehaviorScore object.
        """
        if self.client:
            prompt = (
                "Analyze the following agent tool call execution context and verdict, and score "
                "the behavioral drift on a scale of 0 to 5 (where 0 is baseline/benign, and 5 "
                "is high risk/malicious evasion/drift).\n"
                f"Event details:\n{event.model_dump_json()}\n"
                "Return a JSON object with the keys:\n"
                "- score: float (0.0 to 5.0)\n"
                "- risk_level: string ('LOW', 'MEDIUM', 'HIGH', or 'CRITICAL')"
            )
            try:
                create_fn = self.client.interactions.create
                if asyncio.iscoroutinefunction(create_fn):
                    interaction = await create_fn(
                        model="gemini-3.1-flash-lite",
                        input=prompt,
                    )
                else:
                    interaction = create_fn(
                        model="gemini-3.1-flash-lite",
                        input=prompt,
                    )
                output_text = getattr(interaction, "output_text", "") or ""
                # Clean markdown blocks
                if output_text.strip().startswith("```"):
                    lines = output_text.strip().splitlines()
                    if len(lines) > 2:
                        output_text = "\n".join(lines[1:-1])
                data = json.loads(output_text)
                score_0_5 = float(data["score"])
                # Normalize to [0.0, 1.0]
                normalized_score = max(0.0, min(score_0_5 / 5.0, 1.0))
                risk_level = str(data["risk_level"])
                return BehaviorScore(score=normalized_score, risk_level=risk_level)
            except Exception as e:
                logger.error(f"LLM-as-judge scoring failed: {e}")

        # Heuristic fallback if client is missing or fails
        score_val = 0.0
        if event.event_type == EventType.BLOCK:
            score_val = 4.5
        elif event.event_type == EventType.QUARANTINE:
            score_val = 3.0
        elif event.event_type == EventType.ALLOW:
            score_val = 1.0

        normalized = score_val / 5.0
        risk_level = "LOW"
        if score_val >= 4.0:
            risk_level = "CRITICAL"
        elif score_val >= 2.5:
            risk_level = "HIGH"
        elif score_val >= 1.0:
            risk_level = "MEDIUM"

        return BehaviorScore(score=normalized, risk_level=risk_level)

    def detectDrift(
        self, current_score_normalized: float, baseline_score: Optional[float] = None
    ) -> bool:
        """
        Detects anomalies when drift exceeds the tolerance band of ±0.5 on the 0-5 scale.
        """
        base = baseline_score if baseline_score is not None else self.baseline_score
        # Calculate scores on the 0-5 scale
        current_val = current_score_normalized * 5.0
        drift = abs(current_val - base)
        return drift > 0.5

    async def generateSignature(self, event: SecurityEvent) -> ThreatSignature:
        """
        Extracts attacker intent, generalizes payload, computes similarity vector,
        determines mitigation action, and returns a ThreatSignature.
        """
        tool_name = event.tool_context.tool_name
        raw_args = event.tool_context.arguments

        # 1. Extract attacker intent from semantic gating reason field
        attacker_intent = "Suspicious tool usage"
        if event.verdict and event.verdict.reasoning:
            attacker_intent = event.verdict.reasoning

        # 2. Generalize payload pattern (handle CommandLine in run_command specifically)
        cmd = raw_args.get("CommandLine") or raw_args.get("command") or raw_args.get("cmd")
        if tool_name == "run_command" and isinstance(cmd, str):
            payload_pattern = self._generalize_string(cmd)
        else:
            payload_pattern = self._generalize_payload(raw_args)

        # 3. NO REDUNDANT CBM QUERY: read directly from cbm_response
        has_critical_sink = False
        sink_type = SinkType.PROCESS
        dep_chain = []
        if event.cbm_response:
            # Check hasCriticalSink directly if present, or infer from list of critical sinks
            if hasattr(event.cbm_response, "hasCriticalSink"):
                has_critical_sink = getattr(event.cbm_response, "hasCriticalSink")
            elif hasattr(event.cbm_response, "critical_sinks") and event.cbm_response.critical_sinks:
                has_critical_sink = len(event.cbm_response.critical_sinks) > 0

            # Map the primary critical sink type to SinkType
            if hasattr(event.cbm_response, "critical_sinks") and event.cbm_response.critical_sinks:
                sink_type = event.cbm_response.critical_sinks[0]

            # Map dependency chain
            if hasattr(event.cbm_response, "dependency_chain"):
                dep_chain = getattr(event.cbm_response, "dependency_chain")

        # 4. Determine mitigation action
        is_gti_malicious = False
        if event.gti_response:
            is_gti_malicious = event.gti_response.is_malicious

        if has_critical_sink:
            mitigation_action = "BLOCK_AND_QUARANTINE_CODE_PATH"
        elif is_gti_malicious:
            mitigation_action = "BLOCK_AND_ALERT_SECURITY_TEAM"
        else:
            mitigation_action = "BLOCK_AND_LOG"

        # 5. Generate similarity vector
        combined_text = f"{attacker_intent} {payload_pattern} {tool_name}"
        vector = None
        sig_id = uuid4()
        if self.embedding_client:
            try:
                vector = await asyncio.wait_for(
                    self.embedding_client.embed(combined_text),
                    timeout=5.0
                )
            except Exception as e:
                logger.warning(
                    "Gemini embedding API call failed or timed out: %s. Falling back to local embedding.",
                    str(e),
                    extra={"signature_id": str(sig_id), "error": str(e)},
                )
                # Fallback to local embedding when Gemini call errors
                vector = self._get_embedding(combined_text)
        else:
            # Fallback to local/mock embedding when client is not configured
            vector = self._get_embedding(combined_text)

        # 6. Construct ThreatSignature Pydantic model
        signature = ThreatSignature(
            signature_id=sig_id,
            pattern=payload_pattern,
            created_at=datetime.now(timezone.utc),
            description=attacker_intent,
            sink_type=sink_type,
        )

        # Write to SQLiteThreatRepository if available
        if self.repo:
            sig_data = {
                "signatureId": str(sig_id),
                "createdAt": int(signature.created_at.timestamp()),
                "attackerIntent": attacker_intent,
                "payloadPattern": payload_pattern,
                "targetTool": tool_name,
                "targetSink": sink_type.value if hasattr(sink_type, "value") else str(sink_type),
                "dependencyChain": dep_chain,
                "mitigationAction": mitigation_action,
                "similarityVector": vector,
                "metadata": {
                    "vibe_trajectory_enabled": True,
                    "event_source": str(event.event_id),
                },
            }
            await self.repo.writeSignature(sig_data)

        # OpenTelemetry Instrumentation (emit span if tracer is present)
        if self.tracer:
            with self.tracer.start_as_current_span("generate_signature") as span:
                span.set_attribute("signature_id", str(sig_id))
                span.set_attribute("tool_name", tool_name)
                span.set_attribute("mitigation_action", mitigation_action)

        return signature

    async def triggerRefactoring(self, event: SecurityEvent) -> RefactoringHint:
        """
        Analyzes quarantined code paths to suggest refactoring hints.
        Completes within 5 seconds to avoid blocking agent execution.
        """
        start_time = time.time()
        vulnerability_type = "Unspecified Vulnerability"
        suggested_fix = "Apply defense-in-depth sanitization."
        confidence = 0.5
        target_code = None

        # Extract target code and sinks from CBM if available
        if event.cbm_response and hasattr(event.cbm_response, "critical_sinks") and event.cbm_response.critical_sinks:
            sink = event.cbm_response.critical_sinks[0]
            if sink == SinkType.DATABASE:
                vulnerability_type = "SQL Injection"
                suggested_fix = "Use parameterized queries instead of string concatenation."
                confidence = 0.9
            elif sink == SinkType.PROCESS:
                vulnerability_type = "Command Injection"
                suggested_fix = "Avoid shell execution. Use subprocess with argument lists."
                confidence = 0.95
            elif sink == SinkType.FILE_SYSTEM:
                vulnerability_type = "Path Traversal"
                suggested_fix = "Validate and sanitize file paths. Ensure they remain within directory bounds."
                confidence = 0.85
            elif sink == SinkType.NETWORK:
                vulnerability_type = "Server-Side Request Forgery (SSRF)"
                suggested_fix = "Validate and whitelist target URLs. Do not request arbitrary client-controlled IPs."
                confidence = 0.8

        target_code = event.tool_context.arguments.get("CommandLine") or event.tool_context.arguments.get("path") or event.tool_context.arguments.get("url")
        target_code_str = str(target_code) if target_code else None

        # If LLM client is available, run a quick refactoring analysis (max 5s timeout)
        if self.client:
            prompt = (
                "Suggest a refactoring fix for the following quarantined action:\n"
                f"Tool Call: {event.tool_context.tool_name}\n"
                f"Arguments: {json.dumps(event.tool_context.arguments)}\n"
                "Return a JSON object containing:\n"
                "- suggestion: string (short description of the suggestion)\n"
                "- confidence: float (0.0 to 1.0)\n"
                "- vulnerability_type: string\n"
                "- suggested_fix: string (concrete code fix description)"
            )
            try:
                # 4.8s timeout limit to guarantee returning within 5.0 seconds
                create_fn = self.client.interactions.create
                if asyncio.iscoroutinefunction(create_fn):
                    interaction = await asyncio.wait_for(
                        create_fn(model="gemini-3.1-flash-lite", input=prompt),
                        timeout=max(0.1, 4.8 - (time.time() - start_time)),
                    )
                else:
                    interaction = await asyncio.wait_for(
                        asyncio.to_thread(
                            create_fn, model="gemini-3.1-flash-lite", input=prompt
                        ),
                        timeout=max(0.1, 4.8 - (time.time() - start_time)),
                    )
                output_text = getattr(interaction, "output_text", "") or ""
                if output_text.strip().startswith("```"):
                    lines = output_text.strip().splitlines()
                    if len(lines) > 2:
                        output_text = "\n".join(lines[1:-1])
                data = json.loads(output_text)
                confidence = float(data["confidence"])
                vulnerability_type = str(data["vulnerability_type"])
                suggested_fix = str(data["suggested_fix"])
            except Exception as e:
                logger.warning(f"LLM refactoring generation timed out or failed: {e}. Using heuristics.")

        suggestion_str = f"Vulnerability: {vulnerability_type}. Suggested Fix: {suggested_fix}"
        hint = RefactoringHint(
            hint_id=uuid4(),
            suggestion=suggestion_str,
            confidence=confidence,
            target_code=target_code_str,
            vulnerability_type=vulnerability_type,
            suggested_fix=suggested_fix,
        )

        # Write refactoring hint in threat signature metadata if signature is present in SQLite
        if self.repo and event.related_signatures:
            # Update the metadata of the related signatures
            for sig_id in event.related_signatures:
                # For demo purposes, we can update the database row
                async with self.repo.pool.connection() as conn:
                    # Retrieve existing metadata
                    cursor = await conn.execute(
                        "SELECT metadata FROM signatures WHERE signature_id = ?",
                        (str(sig_id),),
                    )
                    row = await cursor.fetchone()
                    meta_dict = {}
                    if row and row[0]:
                        try:
                            meta_dict = json.loads(row[0])
                        except Exception:
                            pass
                    meta_dict["refactoring_hint"] = hint.model_dump(mode="json")
                    await conn.execute(
                        "UPDATE signatures SET metadata = ? WHERE signature_id = ?",
                        (json.dumps(meta_dict), str(sig_id)),
                    )

        return hint

    def updateAgBOM(self, event: SecurityEvent) -> None:
        """
        Updates the runtime AgBOM inventory of agent capabilities, frequencies,
        and argument patterns. Logs anomaly event if capability drift is detected.
        """
        tool_name = event.tool_context.tool_name
        if tool_name not in self.agbom["tools"]:
            self.agbom["tools"][tool_name] = {"frequency": 0, "argument_patterns": []}

        self.agbom["tools"][tool_name]["frequency"] += 1

        arg_pattern = sorted(list(event.tool_context.arguments.keys()))
        if arg_pattern not in self.agbom["tools"][tool_name]["argument_patterns"]:
            self.agbom["tools"][tool_name]["argument_patterns"].append(arg_pattern)

        # Detect capability drift
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            logger.error(
                f"Capability drift detected: Unexpected tool '{tool_name}' used.",
                extra={
                    "tool": tool_name,
                    "allowed_tools": list(self.allowed_tools),
                },
            )
            # Log anomaly event as eventType SIGNATURE_CREATED
            anomaly_event = SecurityEvent(
                event_type=EventType.SIGNATURE_CREATED,
                tool_context=event.tool_context,
                verdict=None,
                behavior_score=BehaviorScore(score=1.0, risk_level="CRITICAL"),
                agent_id=event.agent_id,
            )
            logger.info("ANOMALY_EVENT_LOGGED", event=anomaly_event.model_dump(mode="json"))

    def exportAgBOM(self) -> str:
        """
        Exports AgBOM inventory as structured JSON.
        """
        return json.dumps(self.agbom, indent=2)


class Agent_Behavioral_Analytics:
    @staticmethod
    async def generateSignature(candidate: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stub for generating a signature from a candidate payload.
        This will be fully implemented in Task 11.
        """
        # For now, just return the candidate as the signature.
        return candidate

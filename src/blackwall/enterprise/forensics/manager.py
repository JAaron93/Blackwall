"""
Forensic Triage Manager (`blackwall.enterprise.forensics.manager`).
Orchestrates dual-mode out-of-band forensic execution:
1. Primary: Local Ollama LLM endpoint (Qwen3 / GLM-5.2)
2. Standalone Fallback: LightweightForensicParser (regex/AST heuristics)
Integrates with OpenTelemetryMCPAdapter to automatically stream incident trace spans.
"""

import logging
import uuid
from typing import Any, Dict, Optional

from blackwall.enterprise.forensics.fallback_parser import LightweightForensicParser
from blackwall.enterprise.forensics.ollama_engine import OllamaForensicEngine
from blackwall.enterprise.mcp.opentelemetry_mcp import OpenTelemetryMCPAdapter

logger = logging.getLogger(__name__)


class ForensicTriageManager:
    """Orchestrator for out-of-band dual-mode forensic log triage & OTel trace export."""

    def __init__(
        self,
        ollama_engine: Optional[OllamaForensicEngine] = None,
        fallback_parser: Optional[LightweightForensicParser] = None,
        otel_adapter: Optional[OpenTelemetryMCPAdapter] = None,
    ) -> None:
        self.ollama_engine: OllamaForensicEngine = ollama_engine or OllamaForensicEngine()
        self.fallback_parser: LightweightForensicParser = fallback_parser or LightweightForensicParser()
        self.otel_adapter: Optional[OpenTelemetryMCPAdapter] = otel_adapter

    async def triage_log_event(self, log_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute dual-mode forensic log triage:
        - Query Ollama health check. If online, process via Ollama LLM.
        - If Ollama is unreachable/offline, failover to LightweightForensicParser.
        - Export telemetry span via OpenTelemetryMCPAdapter if connected.
        """
        trace_id = f"tr_{uuid.uuid4().hex[:12]}"
        is_ollama_active = await self.ollama_engine.is_ollama_online()

        if is_ollama_active:
            logger.info("Ollama LLM online. Executing Primary Ollama Forensic Triage.")
            report = await self.ollama_engine.analyze_log_stream(log_payload)
        else:
            logger.info("Ollama LLM offline. Executing Standalone Lightweight Fallback Parser.")
            report = self.fallback_parser.parse(log_payload)

        report["trace_id"] = trace_id
        otel_exported = False

        if self.otel_adapter and self.otel_adapter.is_connected:
            try:
                span_attributes = {
                    "forensic_mode": report.get("mode", "unknown"),
                    "is_threat": report.get("is_threat", False),
                    "threat_level": report.get("threat_level", "LOW"),
                    "extracted_pattern": report.get("extracted_pattern", ""),
                }
                await self.otel_adapter.export_trace_span(
                    trace_id=trace_id,
                    span_name="forensic_log_triage",
                    attributes=span_attributes,
                )
                otel_exported = True
            except Exception as err:
                logger.warning("Failed to export OTel span during triage: %s", err)

            try:
                await self.otel_adapter.ingest_log_event(log_payload)
            except Exception as err:
                logger.warning("Failed to ingest OTel log event during triage: %s", err)

        report["otel_span_exported"] = otel_exported
        return report

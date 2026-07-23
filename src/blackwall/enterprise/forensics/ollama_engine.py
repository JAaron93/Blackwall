"""
Primary Ollama Open-Weight LLM Triage Engine (`blackwall.enterprise.forensics.ollama_engine`).
Streams telemetry log events to local Ollama LLM endpoint (Qwen3 / GLM-5.2) without cloud safety refusals.
"""

import json
import logging
import re
from typing import Any, Dict, Optional
import aiohttp

logger = logging.getLogger(__name__)


class OllamaForensicEngine:
    """Primary out-of-band LLM log stream analyzer powered by local Ollama endpoint."""

    def __init__(
        self,
        endpoint: str = "http://localhost:11434",
        model: str = "qwen3:8b",
        timeout: float = 3.0,
    ) -> None:
        self.endpoint: str = endpoint.rstrip("/")
        self.model: str = model
        self.timeout: float = timeout

    async def is_ollama_online(self) -> bool:
        """Health check verifying if local Ollama daemon is reachable and responding."""
        try:
            url = f"{self.endpoint}/api/tags"
            timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                async with session.get(url) as resp:
                    return resp.status == 200
        except Exception as err:
            logger.debug("Ollama health check failed: %s", err)
            return False

    async def analyze_log_stream(self, log_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze incoming log payload using local Ollama LLM endpoint.
        Returns forensic triage report dict.
        """
        prompt = (
            "You are Blackwall's local forensic security analyst. Analyze the following log event for exploits, "
            "reverse shells, credential exfiltration, or malicious commands:\n"
            f"{json.dumps(log_payload)}\n"
            'Respond ONLY with valid JSON in format: {"is_threat": bool, "threat_level": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW", '
            '"description": str, "extracted_pattern": str}'
        )

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        try:
            url = f"{self.endpoint}/api/generate"
            timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        res_json = await resp.json()
                        raw_response = res_json.get("response", "")
                        return self._parse_llm_json_response(raw_response)
                    else:
                        logger.warning("Ollama API returned HTTP %d", resp.status)
        except Exception as err:
            logger.warning("Ollama log analysis failed: %s", err)

        # Fallback response if HTTP call failed internally
        return {
            "is_threat": False,
            "threat_level": "LOW",
            "mode": "ollama_primary",
            "model": self.model,
            "description": "Ollama LLM analysis unavailable",
            "extracted_pattern": "",
        }

    def _parse_llm_json_response(self, raw_text: str) -> Dict[str, Any]:
        """Extract and parse JSON output from Ollama LLM response string."""
        try:
            # Clean possible markdown code fences
            cleaned = raw_text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

            parsed = json.loads(cleaned)
            return {
                "is_threat": bool(parsed.get("is_threat", False)),
                "threat_level": str(parsed.get("threat_level", "LOW")),
                "mode": "ollama_primary",
                "model": self.model,
                "description": str(parsed.get("description", "LLM triage complete")),
                "extracted_pattern": str(parsed.get("extracted_pattern", "")),
            }
        except Exception as err:
            logger.debug("Failed to parse Ollama JSON response: %s", err)
            # Check for explicit key pattern or return neutral fallback instead of prose substring search
            is_threat = bool(re.search(r'"is_threat"\s*:\s*true', raw_text, re.IGNORECASE))
            threat_level = "LOW"
            if is_threat:
                if re.search(r'"threat_level"\s*:\s*"CRITICAL"', raw_text, re.IGNORECASE):
                    threat_level = "CRITICAL"
                elif re.search(r'"threat_level"\s*:\s*"HIGH"', raw_text, re.IGNORECASE):
                    threat_level = "HIGH"
                else:
                    threat_level = "MEDIUM"

            return {
                "is_threat": is_threat,
                "threat_level": threat_level,
                "mode": "ollama_primary",
                "model": self.model,
                "description": f"Ollama response non-standard JSON fallback: {raw_text[:200]}",
                "extracted_pattern": raw_text[:100] if is_threat else "",
            }

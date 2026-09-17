"""Harpoon OSINT Companion Bridge.

Provides subprocess execution of the `harpoon` OSINT CLI tool with automatic liveness
detection and transparent fallback to AlienVaultOTXProvider.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import Any, Dict, List, Optional, Set

from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelProvider,
    ThreatIntelResponse,
)
from blackwall.threat_intel.otx import (
    AlienVaultOTXProvider,
    _sanitize_indicator_for_log,
)

logger = logging.getLogger("blackwall.threat_intel.harpoon")


class HarpoonError(Exception):
    """Base exception for Harpoon companion bridge operations."""

    pass


class HarpoonExecutionError(HarpoonError):
    """Exception raised when harpoon CLI process returns a non-zero exit code."""

    pass


class HarpoonTimeoutError(HarpoonError):
    """Exception raised when harpoon subprocess execution exceeds timeout."""

    pass


class HarpoonParseError(HarpoonError):
    """Exception raised when harpoon JSON stdout cannot be parsed."""

    pass


class HarpoonBridge:
    """Subprocess runner for harpoon OSINT CLI with transparent fallback."""

    name: str = "harpoon"
    supported_indicators: Set[ThreatIndicatorType] = {
        ThreatIndicatorType.IPV4,
        ThreatIndicatorType.IPV6,
        ThreatIndicatorType.DOMAIN,
        ThreatIndicatorType.URL,
        ThreatIndicatorType.FILE_HASH,
    }

    _SUBCOMMAND_MAP = {
        ThreatIndicatorType.IPV4: "ip",
        ThreatIndicatorType.IPV6: "ip",
        ThreatIndicatorType.DOMAIN: "domain",
        ThreatIndicatorType.URL: "url",
        ThreatIndicatorType.FILE_HASH: "hash",
    }

    def __init__(
        self,
        harpoon_bin: str = "harpoon",
        fallback_provider: Optional[ThreatIntelProvider] = None,
        timeout: float = 5.0,
    ) -> None:
        self.harpoon_bin = harpoon_bin
        self.timeout = timeout
        self.fallback_provider = (
            fallback_provider if fallback_provider is not None else AlienVaultOTXProvider()
        )

    def is_available(self) -> bool:
        """Check if harpoon executable is present on system PATH."""
        return bool(shutil.which(self.harpoon_bin))

    def _map_subcommand(self, indicator_type: ThreatIndicatorType) -> str:
        subcmd = self._SUBCOMMAND_MAP.get(indicator_type)
        if not subcmd:
            raise ValueError(f"Unsupported indicator type for harpoon: {indicator_type}")
        return subcmd

    async def _execute_harpoon(
        self,
        subcmd: str,
        indicator: str,
        indicator_type: ThreatIndicatorType = ThreatIndicatorType.IPV4,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Execute harpoon subprocess and parse JSON output."""
        cmd = [self.harpoon_bin, "otx", subcmd, indicator, "--json"]
        sanitized_ind = _sanitize_indicator_for_log(indicator, indicator_type)
        sanitized_cmd = [self.harpoon_bin, "otx", subcmd, sanitized_ind, "--json"]
        logger.debug("Executing Harpoon command: %s", " ".join(sanitized_cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError as te:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            raise HarpoonTimeoutError(
                f"Harpoon subprocess timed out after {timeout} seconds"
            ) from te

        if proc.returncode != 0:
            err_msg = stderr.decode(errors="replace").strip()
            raise HarpoonExecutionError(
                f"Harpoon process exited with status {proc.returncode}: {err_msg}"
            )

        try:
            return json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as jde:
            raise HarpoonParseError(
                f"Failed to parse JSON output from Harpoon: {jde}"
            ) from jde

    def _parse_harpoon_response(
        self,
        indicator: str,
        indicator_type: ThreatIndicatorType,
        raw: Any,
    ) -> ThreatIntelResponse:
        """Parse raw harpoon output dictionary or list into ThreatIntelResponse."""
        if isinstance(raw, dict):
            pulse_info = raw.get("pulse_info", {})
            if isinstance(pulse_info, dict):
                count = pulse_info.get("count", 0)
                pulses = pulse_info.get("pulses", [])
            else:
                count = raw.get("count", 0)
                pulses = raw.get("pulses", [])
        elif isinstance(raw, list):
            pulses = raw
            count = len(pulses)
            raw = {"pulse_info": {"count": count, "pulses": pulses}}
        else:
            pulses = []
            count = 0
            raw = {}

        threat_categories: Set[str] = set()
        malware_families: Set[str] = set()
        references: List[str] = []
        malware_pulse_count = 0

        high_risk_tags = {
            "c2",
            "command and control",
            "trojan",
            "stealer",
            "infostealer",
            "ransomware",
            "backdoor",
            "botnet",
            "apt",
            "exploit",
        }

        for pulse in pulses:
            if not isinstance(pulse, dict):
                continue
            tags = [str(t).lower() for t in pulse.get("tags", [])]
            threat_categories.update(tags)

            pulse_malware = pulse.get("malware_families", [])
            has_malware = False
            for mf in pulse_malware:
                if isinstance(mf, dict) and "display_name" in mf:
                    malware_families.add(mf["display_name"])
                    has_malware = True
                elif isinstance(mf, str):
                    malware_families.add(mf)
                    has_malware = True

            if has_malware or any(t in high_risk_tags for t in tags):
                malware_pulse_count += 1

            for ref in pulse.get("references", []):
                if ref and ref not in references:
                    references.append(ref)

        raw_risk = (count * 0.25) + (malware_pulse_count * 0.50)
        risk_score = min(1.0, max(0.0, raw_risk))
        is_malicious = risk_score >= 0.25 or malware_pulse_count > 0

        return ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=is_malicious,
            risk_score=round(risk_score, 2),
            detection_count=malware_pulse_count,
            total_engines=count,
            threat_categories=sorted(list(threat_categories)),
            malware_families=sorted(list(malware_families)),
            pulse_count=count,
            references=references[:10],
            provider_name=self.name,
            cached=False,
            raw_response=raw if isinstance(raw, dict) else {},
        )

    async def lookup(
        self,
        indicator: str,
        indicator_type: ThreatIndicatorType,
        timeout: Optional[float] = None,
    ) -> ThreatIntelResponse:
        """Query indicator via harpoon, transparently falling back to OTX on absence or failure."""
        effective_timeout = timeout if timeout is not None else self.timeout

        if not self.is_available():
            logger.info(
                "Harpoon executable '%s' not found on PATH. Falling back to built-in AlienVaultOTXProvider.",
                self.harpoon_bin,
            )
            return await self.fallback_provider.lookup(
                indicator, indicator_type, timeout=effective_timeout
            )

        subcmd = self._map_subcommand(indicator_type)
        sanitized_ind = _sanitize_indicator_for_log(indicator, indicator_type)
        try:
            raw_data = await self._execute_harpoon(
                subcmd, indicator, indicator_type, timeout=effective_timeout
            )
            return self._parse_harpoon_response(indicator, indicator_type, raw_data)
        except Exception as exc:
            exc_str = str(exc)
            if indicator in exc_str:
                exc_str = exc_str.replace(indicator, sanitized_ind)
            logger.info(
                "Harpoon execution failed for %s (%s). Transparently falling back to AlienVaultOTXProvider.",
                sanitized_ind,
                exc_str,
            )
            return await self.fallback_provider.lookup(
                indicator, indicator_type, timeout=effective_timeout
            )

    async def is_healthy(self) -> bool:
        """Check bridge health or fallback provider health."""
        if self.is_available():
            return True
        return await self.fallback_provider.is_healthy()

    def get_remaining_budget(self) -> int:
        """Return remaining quota from fallback provider or unlimited."""
        return self.fallback_provider.get_remaining_budget()

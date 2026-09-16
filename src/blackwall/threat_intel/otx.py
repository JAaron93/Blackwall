"""AlienVault OTX Threat Intelligence Provider.

Implements high-throughput (10,000 req/hr) async threat intelligence lookups
with token bucket rate limiting and 3-state circuit breaker resilience.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import hashlib
import urllib.parse
from typing import Any, Dict, List, Optional, Set

import aiohttp

from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)

logger = logging.getLogger("blackwall.threat_intel.otx")


class ThreatIntelError(Exception):
    """Base exception for threat intelligence operations."""

    pass


class OTXCircuitBreakerOpenError(ThreatIntelError):
    """Exception raised when AlienVault OTX circuit breaker is OPEN (degraded)."""

    pass


class OTXTokenBucketExhaustedError(ThreatIntelError):
    """Exception raised when AlienVault OTX token bucket is exhausted."""

    pass


class OTXLookupError(ThreatIntelError):
    """Exception raised when AlienVault OTX HTTP query fails."""

    pass


def _sanitize_indicator_for_log(
    indicator: str, indicator_type: ThreatIndicatorType
) -> str:
    """Sanitize indicator to prevent credentials or secret tokens from leaking into logs."""
    if indicator_type == ThreatIndicatorType.URL or "://" in indicator:
        try:
            parsed = urllib.parse.urlsplit(indicator)
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            query = "[REDACTED]" if parsed.query else ""
            fragment = "[REDACTED]" if parsed.fragment else ""
            return urllib.parse.urlunsplit(
                (parsed.scheme, netloc, parsed.path, query, fragment)
            )
        except Exception:
            return hashlib.sha256(indicator.encode("utf-8")).hexdigest()[:16]
    return indicator


class OTXTokenBucket:
    """Thread-safe token bucket rate limiter for AlienVault OTX.

    Default: 10,000 tokens capacity, replenishing 1 token every 0.36 seconds (~166 RPM).
    """

    def __init__(
        self,
        capacity: int = 10000,
        replenishment_interval: float = 0.36,
    ) -> None:
        self.capacity = capacity
        self.replenishment_interval = replenishment_interval
        self.tokens = float(capacity)
        self.lock = asyncio.Lock()
        self.last_replenish = time.monotonic()

    def _replenish_unlocked(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_replenish
        tokens_to_add = elapsed / self.replenishment_interval
        if tokens_to_add >= 1.0:
            self.tokens = min(float(self.capacity), self.tokens + tokens_to_add)
            self.last_replenish = now

    async def try_acquire(self) -> bool:
        async with self.lock:
            self._replenish_unlocked()
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    def get_available_tokens(self) -> int:
        self._replenish_unlocked()
        return int(self.tokens)


class AlienVaultOTXProvider:
    """AlienVault Open Threat Exchange (OTX) provider implementation."""

    name: str = "otx"
    supported_indicators: Set[ThreatIndicatorType] = {
        ThreatIndicatorType.IPV4,
        ThreatIndicatorType.IPV6,
        ThreatIndicatorType.DOMAIN,
        ThreatIndicatorType.URL,
        ThreatIndicatorType.FILE_HASH,
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://otx.alienvault.com/api/v1",
        cooldown_seconds: float = 60.0,
    ) -> None:
        self.api_key = self._resolve_api_key(api_key)
        self.base_url = base_url.rstrip("/")
        self.cooldown_seconds = cooldown_seconds

        # 10,000 req/hr if authenticated, 1,000 req/hr if unauthenticated
        capacity = 10000 if self.api_key else 1000
        interval = 0.36 if self.api_key else 3.6
        self.token_bucket = OTXTokenBucket(
            capacity=capacity, replenishment_interval=interval
        )

        # 3-State Circuit Breaker
        self._circuit_state = "CLOSED"  # CLOSED, OPEN, HALF-OPEN
        self.consecutive_failures = 0
        self.last_state_change = 0.0
        self.successful_probes = 0

    def _resolve_api_key(self, explicit_key: Optional[str]) -> str:
        """Resolve AlienVault OTX API key from argument, environment, or config.yaml."""
        if explicit_key and explicit_key.strip():
            return explicit_key.strip()

        env_key = os.environ.get("BW_OTX_API_KEY", "").strip()
        if env_key:
            return env_key

        config_path = os.path.expanduser("~/.blackwall/config.yaml")
        if os.path.exists(config_path):
            try:
                import yaml

                with open(config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                if isinstance(data, dict):
                    threat_intel = data.get("threat_intel")
                    if isinstance(threat_intel, dict):
                        key = threat_intel.get("otx_api_key") or threat_intel.get("otx", {}).get("api_key")
                        if key and str(key).strip():
                            return str(key).strip()
                    flat_key = data.get("otx_api_key") or data.get("BW_OTX_API_KEY")
                    if flat_key and str(flat_key).strip():
                        return str(flat_key).strip()
            except Exception as e:
                logger.debug("Failed reading %s: %s", config_path, e)

        logger.warning(
            "No AlienVault OTX API key configured (checked constructor, BW_OTX_API_KEY, and ~/.blackwall/config.yaml). "
            "Running in degraded unauthenticated mode (1,000 req/hr)."
        )
        return ""

    @property
    def circuit_state(self) -> str:
        if self._circuit_state == "OPEN":
            if time.time() - self.last_state_change > self.cooldown_seconds:
                self._circuit_state = "HALF-OPEN"
                self.successful_probes = 0
                logger.info("OTX Provider moving from OPEN to HALF-OPEN")
        return self._circuit_state

    @circuit_state.setter
    def circuit_state(self, value: str) -> None:
        self._circuit_state = value

    def get_remaining_budget(self) -> int:
        return self.token_bucket.get_available_tokens()

    async def is_healthy(self) -> bool:
        return self.circuit_state != "OPEN"

    def _check_circuit_breaker(self) -> bool:
        return self.circuit_state != "OPEN"

    def _record_success(self) -> None:
        self.consecutive_failures = 0
        if self.circuit_state == "HALF-OPEN":
            self.successful_probes += 1
            if self.successful_probes >= 3:
                self.circuit_state = "CLOSED"
                self.successful_probes = 0
                logger.info("OTX Provider circuit restored to CLOSED after 3 successful probes")

    def _record_failure(self) -> None:
        self.consecutive_failures += 1
        if self.circuit_state == "HALF-OPEN" or self.consecutive_failures >= 5:
            self.circuit_state = "OPEN"
            self.last_state_change = time.time()
            self.successful_probes = 0
            logger.warning(
                "OTX Provider tripped circuit breaker. Switched to OPEN (degraded) mode."
            )

    def _map_endpoint(
        self, indicator: str, indicator_type: ThreatIndicatorType
    ) -> str:
        if indicator_type == ThreatIndicatorType.IPV4:
            return f"indicators/IPv4/{indicator}/general"
        elif indicator_type == ThreatIndicatorType.IPV6:
            return f"indicators/IPv6/{indicator}/general"
        elif indicator_type == ThreatIndicatorType.DOMAIN:
            return f"indicators/domain/{indicator}/general"
        elif indicator_type == ThreatIndicatorType.URL:
            import urllib.parse

            encoded = urllib.parse.quote(indicator, safe="")
            return f"indicators/url/{encoded}/general"
        elif indicator_type == ThreatIndicatorType.FILE_HASH:
            return f"indicators/file/{indicator}/general"
        else:
            raise ValueError(f"Unsupported indicator type: {indicator_type}")

    async def _execute_http_get(self, endpoint: str) -> Dict[str, Any]:
        """Executes async HTTP GET request against OTX API."""
        url = f"{self.base_url}/{endpoint}"
        headers = {"User-Agent": "Blackwall-Firewall/3.0"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        timeout = aiohttp.ClientTimeout(total=3.0)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 404:
                    return {"indicator": "", "pulse_info": {"count": 0, "pulses": []}}
                if response.status >= 400:
                    raise ConnectionError(
                        f"OTX API returned HTTP error: {response.status}"
                    )
                return await response.json()

    def _parse_otx_response(
        self, indicator: str, indicator_type: ThreatIndicatorType, raw: Dict[str, Any]
    ) -> ThreatIntelResponse:
        pulse_info = raw.get("pulse_info", {})
        count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])

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

        # Risk scoring formula
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
            raw_response=raw,
        )

    async def lookup(
        self,
        indicator: str,
        indicator_type: ThreatIndicatorType,
        timeout: float = 3.0,
    ) -> ThreatIntelResponse:
        """Looks up threat intelligence for an indicator with rate limit & circuit breaker protection."""
        sanitized = _sanitize_indicator_for_log(indicator, indicator_type)
        if not self._check_circuit_breaker():
            logger.warning(
                "OTX circuit breaker is OPEN. Failing fast for %s",
                sanitized,
            )
            raise OTXCircuitBreakerOpenError(
                f"OTX circuit breaker is OPEN for indicator: {sanitized}"
            )

        acquired = await self.token_bucket.try_acquire()
        if not acquired:
            logger.warning("OTX token bucket exhausted for indicator: %s", sanitized)
            raise OTXTokenBucketExhaustedError(
                f"OTX token bucket exhausted for indicator: {sanitized}"
            )

        endpoint = self._map_endpoint(indicator, indicator_type)
        try:
            raw = await asyncio.wait_for(
                self._execute_http_get(endpoint), timeout=timeout
            )
            self._record_success()
            return self._parse_otx_response(indicator, indicator_type, raw)
        except Exception as e:
            logger.warning("OTX lookup failed for %s: %s", sanitized, str(e))
            self._record_failure()
            raise OTXLookupError(
                f"OTX lookup failed for {sanitized}: {str(e)}"
            ) from e

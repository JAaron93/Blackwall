"""AbuseIPDB Threat Intelligence Provider.

Implements dedicated IP reputation lookups via the AbuseIPDB v2 API
with linear confidence score mapping and strict IP indicator scoping.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict, Optional, Set

import aiohttp

from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)

logger = logging.getLogger("blackwall.threat_intel.abuseipdb")

ABUSEIPDB_CATEGORIES: Dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBError(Exception):
    """Base exception for AbuseIPDB operations."""

    pass


class AbuseIPDBLookupError(AbuseIPDBError):
    """Exception raised when AbuseIPDB query fails."""

    pass


class AbuseIPDBRateLimitError(AbuseIPDBError):
    """Exception raised when AbuseIPDB rate limit is exceeded."""

    pass


class AbuseIPDBProvider:
    """AbuseIPDB threat intelligence provider implementation."""

    name: str = "abuseipdb"
    supported_indicators: Set[ThreatIndicatorType] = {
        ThreatIndicatorType.IPV4,
        ThreatIndicatorType.IPV6,
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.abuseipdb.com/api/v2",
        max_age_in_days: int = 90,
    ) -> None:
        self.api_key = self._resolve_api_key(api_key)
        self.base_url = base_url.rstrip("/")
        self.max_age_in_days = max_age_in_days
        self._daily_budget = 10000 if self.api_key else 0
        self._remaining_budget = self._daily_budget

    def _resolve_api_key(self, explicit_key: Optional[str]) -> str:
        """Resolve AbuseIPDB API key from argument, environment, or config.yaml."""
        if explicit_key and explicit_key.strip():
            return explicit_key.strip()

        env_key = os.environ.get("BW_ABUSEIPDB_API_KEY", "").strip()
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
                        key = threat_intel.get("abuseipdb_api_key") or threat_intel.get(
                            "abuseipdb", {}
                        ).get("api_key")
                        if key and str(key).strip():
                            return str(key).strip()
                    flat_key = data.get("abuseipdb_api_key") or data.get(
                        "BW_ABUSEIPDB_API_KEY"
                    )
                    if flat_key and str(flat_key).strip():
                        return str(flat_key).strip()
            except Exception as e:
                logger.debug("Failed reading %s: %s", config_path, e)

        logger.info(
            "No AbuseIPDB API key configured (checked constructor, BW_ABUSEIPDB_API_KEY, and ~/.blackwall/config.yaml)."
        )
        return ""

    def get_remaining_budget(self) -> int:
        """Return available request quota balance."""
        return self._remaining_budget

    async def is_healthy(self) -> bool:
        """Check provider connectivity and health."""
        return bool(self.api_key)

    async def _execute_http_get(
        self, endpoint: str, params: Dict[str, str], timeout: float = 3.0
    ) -> Dict[str, Any]:
        """Executes async HTTP GET request against AbuseIPDB API."""
        url = f"{self.base_url}/{endpoint}"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "Blackwall-Firewall/3.0",
        }

        client_timeout = aiohttp.ClientTimeout(total=timeout)
        try:
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 429:
                        raise AbuseIPDBRateLimitError(
                            "AbuseIPDB rate limit exceeded (HTTP 429)"
                        )
                    if response.status >= 400:
                        raise ConnectionError(
                            f"AbuseIPDB API returned HTTP error: {response.status}"
                        )
                    return await response.json()
        except AbuseIPDBRateLimitError:
            raise
        except Exception as e:
            raise ConnectionError(f"HTTP request to AbuseIPDB failed: {e}") from e

    def _parse_abuseipdb_response(
        self, indicator: str, indicator_type: ThreatIndicatorType, raw: Dict[str, Any]
    ) -> ThreatIntelResponse:
        data = raw.get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        total_reports = int(data.get("totalReports", 0))
        distinct_users = int(data.get("numDistinctUsers", 0))

        # Linear mapping: 0-100 -> 0.0-1.0
        risk_score = round(max(0.0, min(1.0, score / 100.0)), 2)
        is_malicious = score >= 25

        categories: Set[str] = set()
        usage_type = data.get("usageType")
        if usage_type:
            categories.add(str(usage_type))

        isp = data.get("isp")
        if isp:
            categories.add(str(isp))

        for report in data.get("reports", []):
            for cat_id in report.get("categories", []):
                cat_name = ABUSEIPDB_CATEGORIES.get(cat_id)
                if cat_name:
                    categories.add(cat_name)

        return ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=is_malicious,
            risk_score=risk_score,
            detection_count=total_reports,
            total_engines=distinct_users,
            threat_categories=sorted(list(categories)),
            malware_families=[],
            pulse_count=total_reports,
            references=[f"https://www.abuseipdb.com/check/{indicator}"],
            provider_name=self.name,
            cached=False,
            raw_response=data,
        )

    async def lookup(
        self,
        indicator: str,
        indicator_type: ThreatIndicatorType,
        timeout: float = 3.0,
    ) -> ThreatIntelResponse:
        """Lookup threat reputation for an IP indicator."""
        if indicator_type not in self.supported_indicators:
            raise ValueError(
                f"AbuseIPDB only supports IP indicators ({', '.join(t.value for t in self.supported_indicators)}), got {indicator_type}"
            )

        if not self.api_key:
            raise AbuseIPDBLookupError("No AbuseIPDB API key configured")

        params = {
            "ipAddress": indicator,
            "maxAgeInDays": str(self.max_age_in_days),
            "verbose": "",
        }

        try:
            raw = await asyncio.wait_for(
                self._execute_http_get("check", params=params, timeout=timeout),
                timeout=timeout,
            )
            if self._remaining_budget > 0:
                self._remaining_budget -= 1
            return self._parse_abuseipdb_response(indicator, indicator_type, raw)
        except AbuseIPDBRateLimitError as e:
            logger.warning("AbuseIPDB rate limit error for %s: %s", indicator, e)
            raise AbuseIPDBLookupError(str(e)) from e
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", indicator, e)
            raise AbuseIPDBLookupError(
                f"AbuseIPDB lookup failed for {indicator}: {str(e)}"
            ) from e

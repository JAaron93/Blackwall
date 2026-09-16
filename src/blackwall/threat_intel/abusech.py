"""abuse.ch Threat Intelligence Provider.

Integrates ThreatFox (IOCs & malware families), URLhaus (malicious URLs),
and MalwareBazaar (malicious payload hashes) into a unified community feed adapter.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Set

import aiohttp

from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)

logger = logging.getLogger("blackwall.threat_intel.abusech")


class AbuseChError(Exception):
    """Base exception for abuse.ch operations."""

    pass


class AbuseChLookupError(AbuseChError):
    """Exception raised when abuse.ch queries fail."""

    pass


class AbuseChRateLimitError(AbuseChLookupError):
    """Exception raised when abuse.ch rate limits are encountered."""

    pass


def _sanitize_indicator_for_log(
    indicator: str, indicator_type: ThreatIndicatorType
) -> str:
    """Sanitize indicator to prevent credentials or secret tokens from leaking into logs."""
    if indicator_type == ThreatIndicatorType.URL or "://" in indicator:
        try:
            import hashlib
            import urllib.parse

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
            import hashlib

            return hashlib.sha256(indicator.encode("utf-8")).hexdigest()[:16]
    return indicator


class AbuseChProvider:
    """abuse.ch multi-feed threat intelligence provider."""

    name: str = "abusech"
    supported_indicators: Set[ThreatIndicatorType] = {
        ThreatIndicatorType.IPV4,
        ThreatIndicatorType.IPV6,
        ThreatIndicatorType.DOMAIN,
        ThreatIndicatorType.URL,
        ThreatIndicatorType.FILE_HASH,
    }


    THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
    URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
    MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(
        self,
        auth_key: Optional[str] = None,
        threatfox_url: Optional[str] = None,
        urlhaus_url: Optional[str] = None,
        malwarebazaar_url: Optional[str] = None,
    ) -> None:
        self.auth_key = self._resolve_auth_key(auth_key)
        self.threatfox_url = threatfox_url or self.THREATFOX_URL
        self.urlhaus_url = urlhaus_url or self.URLHAUS_URL
        self.malwarebazaar_url = malwarebazaar_url or self.MALWAREBAZAAR_URL
        self._budget = 10000

    def _resolve_auth_key(self, explicit_key: Optional[str]) -> str:
        """Resolve abuse.ch Auth-Key from argument, environment, or config.yaml."""
        if explicit_key and explicit_key.strip():
            return explicit_key.strip()

        env_key = os.environ.get("BW_ABUSECH_AUTH_KEY", "").strip()
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
                        key = threat_intel.get("abusech_auth_key") or threat_intel.get(
                            "abusech", {}
                        ).get("auth_key")
                        if key and str(key).strip():
                            return str(key).strip()
                    flat_key = data.get("abusech_auth_key") or data.get(
                        "BW_ABUSECH_AUTH_KEY"
                    )
                    if flat_key and str(flat_key).strip():
                        return str(flat_key).strip()
            except Exception as e:
                logger.debug("Failed reading %s: %s", config_path, e)

        return ""

    def get_remaining_budget(self) -> int:
        """Return available request quota balance."""
        return self._budget

    async def is_healthy(self) -> bool:
        """Check provider connectivity and health."""
        return True

    async def _execute_post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        timeout: float = 3.0,
    ) -> Dict[str, Any]:
        """Executes async HTTP POST request against abuse.ch APIs."""
        headers = {"User-Agent": "Blackwall-Firewall/3.0"}
        if self.auth_key:
            headers["Auth-Key"] = self.auth_key

        client_timeout = aiohttp.ClientTimeout(total=timeout)
        try:
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                kwargs: Dict[str, Any] = {"headers": headers}
                if json_data is not None:
                    kwargs["json"] = json_data
                elif data is not None:
                    kwargs["data"] = data

                async with session.post(url, **kwargs) as response:
                    if response.status == 429:
                        raise AbuseChRateLimitError(
                            "abuse.ch rate limit encountered (HTTP 429)"
                        )
                    if response.status >= 400:
                        raise ConnectionError(
                            f"abuse.ch API returned HTTP error: {response.status}"
                        )
                    json_res = await response.json()
                    if isinstance(json_res, dict):
                        q_status = json_res.get("query_status", "")
                        if q_status in ("rate_limited", "rate_limit"):
                            raise AbuseChRateLimitError(
                                f"abuse.ch API returned rate limit status: {q_status}"
                            )
                    return json_res
        except AbuseChRateLimitError:
            raise
        except Exception as e:
            raise ConnectionError(f"HTTP request to abuse.ch failed: {e}") from e


    async def _lookup_threatfox(
        self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float
    ) -> ThreatIntelResponse:
        payload = {"query": "search_ioc", "search_term": indicator}
        raw = await self._execute_post(self.threatfox_url, json_data=payload, timeout=timeout)

        status = raw.get("query_status", "")
        if status != "ok":
            return ThreatIntelResponse(
                indicator=indicator,
                indicator_type=indicator_type,
                is_malicious=False,
                risk_score=0.0,
                detection_count=0,
                total_engines=0,
                threat_categories=[],
                malware_families=[],
                pulse_count=0,
                references=[],
                provider_name=self.name,
                cached=False,
                raw_response=raw,
            )

        items = raw.get("data") or []
        categories: Set[str] = set()
        malware_families: Set[str] = set()
        max_confidence = 0
        references: List[str] = []

        for item in items:
            if not isinstance(item, dict):
                continue
            conf_val = item.get("confidence_level")
            conf = int(conf_val) if conf_val is not None else 100
            if conf > max_confidence:
                max_confidence = conf

            malware = item.get("malware_printable") or item.get("malware")
            if malware:
                malware_families.add(str(malware))

            threat_type = item.get("threat_type")
            if threat_type:
                categories.add(str(threat_type).lower())

            for tag in item.get("tags") or []:
                if tag:
                    categories.add(str(tag).lower())

            ioc_id = item.get("id")
            if ioc_id:
                references.append(f"https://threatfox.abuse.ch/ioc/{ioc_id}/")

        risk_score = round(max(0.0, min(1.0, max_confidence / 100.0)), 2)
        is_malicious = risk_score >= 0.25 or len(malware_families) > 0

        return ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=is_malicious,
            risk_score=risk_score,
            detection_count=len(items),
            total_engines=len(items),
            threat_categories=sorted(list(categories)),
            malware_families=sorted(list(malware_families)),
            pulse_count=len(items),
            references=references[:10],
            provider_name=self.name,
            cached=False,
            raw_response=raw,
        )

    async def _lookup_urlhaus(
        self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float
    ) -> ThreatIntelResponse:
        data = {"url": indicator}
        raw = await self._execute_post(self.urlhaus_url, data=data, timeout=timeout)

        status = raw.get("query_status", "")
        if status != "ok":
            # Fall back to ThreatFox search if URLhaus has no match
            try:
                tf_resp = await self._lookup_threatfox(indicator, indicator_type, timeout)
                if tf_resp.is_malicious:
                    return tf_resp
            except Exception:
                pass

            return ThreatIntelResponse(
                indicator=indicator,
                indicator_type=indicator_type,
                is_malicious=False,
                risk_score=0.0,
                detection_count=0,
                total_engines=0,
                threat_categories=[],
                malware_families=[],
                pulse_count=0,
                references=[],
                provider_name=self.name,
                cached=False,
                raw_response=raw,
            )

        url_status = raw.get("url_status", "")
        risk_score = 1.0 if url_status == "online" else 0.85
        categories: Set[str] = set()

        threat = raw.get("threat")
        if threat:
            categories.add(str(threat).lower())

        for tag in raw.get("tags") or []:
            if tag:
                categories.add(str(tag).lower())

        references: List[str] = []
        ref = raw.get("urlhaus_reference")
        if ref:
            references.append(str(ref))

        return ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=True,
            risk_score=risk_score,
            detection_count=1,
            total_engines=1,
            threat_categories=sorted(list(categories)),
            malware_families=[],
            pulse_count=1,
            references=references,
            provider_name=self.name,
            cached=False,
            raw_response=raw,
        )

    async def _lookup_malwarebazaar(
        self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float
    ) -> ThreatIntelResponse:
        data = {"query": "get_info", "hash": indicator}
        raw = await self._execute_post(self.malwarebazaar_url, data=data, timeout=timeout)

        status = raw.get("query_status", "")
        if status != "ok":
            # Fall back to ThreatFox search if MalwareBazaar has no match
            try:
                tf_resp = await self._lookup_threatfox(indicator, indicator_type, timeout)
                if tf_resp.is_malicious:
                    return tf_resp
            except Exception:
                pass

            return ThreatIntelResponse(
                indicator=indicator,
                indicator_type=indicator_type,
                is_malicious=False,
                risk_score=0.0,
                detection_count=0,
                total_engines=0,
                threat_categories=[],
                malware_families=[],
                pulse_count=0,
                references=[],
                provider_name=self.name,
                cached=False,
                raw_response=raw,
            )

        items = raw.get("data") or []
        categories: Set[str] = set()
        malware_families: Set[str] = set()
        references: List[str] = []

        for item in items:
            if not isinstance(item, dict):
                continue
            signature = item.get("signature")
            if signature:
                malware_families.add(str(signature))

            for tag in item.get("tags") or []:
                if tag:
                    categories.add(str(tag).lower())

            file_type = item.get("file_type")
            if file_type:
                categories.add(str(file_type).lower())

            sha256 = item.get("sha256_hash")
            if sha256:
                references.append(f"https://bazaar.abuse.ch/sample/{sha256}/")

        return ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=True,
            risk_score=1.0,
            detection_count=len(items) if items else 1,
            total_engines=len(items) if items else 1,
            threat_categories=sorted(list(categories)),
            malware_families=sorted(list(malware_families)),
            pulse_count=len(items) if items else 1,
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
        """Lookup threat reputation across abuse.ch feeds."""
        indicator = indicator.strip()
        if not indicator:
            raise ValueError("Indicator cannot be empty")
        if indicator_type == ThreatIndicatorType.FILE_HASH:
            indicator = indicator.lower()

        if indicator_type not in self.supported_indicators:
            raise ValueError(f"Unsupported indicator type: {indicator_type}")

        sanitized = _sanitize_indicator_for_log(indicator, indicator_type)
        try:
            if indicator_type == ThreatIndicatorType.URL:
                return await self._lookup_urlhaus(indicator, indicator_type, timeout)
            elif indicator_type == ThreatIndicatorType.FILE_HASH:
                return await self._lookup_malwarebazaar(indicator, indicator_type, timeout)
            else:
                return await self._lookup_threatfox(indicator, indicator_type, timeout)
        except AbuseChRateLimitError as e:
            logger.warning("abuse.ch rate limit exceeded for %s: %s", sanitized, e)
            raise AbuseChRateLimitError(
                f"abuse.ch rate limit exceeded for {sanitized}: {e}"
            ) from e
        except Exception as e:
            logger.warning("abuse.ch lookup failed for %s: %s", sanitized, e)
            raise AbuseChLookupError(
                f"abuse.ch lookup failed for {sanitized}: {e}"
            ) from e


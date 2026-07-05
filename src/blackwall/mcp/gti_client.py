"""Google Threat Intelligence (GTI) MCP client wrapper.

Provides stub and production clients for querying threat reputation data.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict

import aiohttp

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import GTIResponse, IndicatorType

logger = logging.getLogger("blackwall.mcp.gti_client")


class GTIClient:
    """Client for querying Google Threat Intelligence MCP server."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> GTIResponse:
        """Lookup threat reputation for an IP address."""
        logger.debug("GTI lookup_ip: %s", ip)
        return GTIResponse(indicator=ip, is_malicious=False)

    async def lookup_url(self, url: str) -> GTIResponse:
        """Lookup threat reputation for a URL."""
        logger.debug("GTI lookup_url: %s", url)
        return GTIResponse(indicator=url, is_malicious=False)

    async def lookup_domain(self, domain: str) -> GTIResponse:
        """Lookup threat reputation for a domain."""
        logger.debug("GTI lookup_domain: %s", domain)
        return GTIResponse(indicator=domain, is_malicious=False)

    async def lookup_file_hash(self, file_hash: str) -> GTIResponse:
        """Lookup threat reputation for a file hash."""
        logger.debug("GTI lookup_file_hash: %s", file_hash)
        return GTIResponse(indicator=file_hash, is_malicious=False)


class GTIDegradedError(Exception):
    """Exception raised when GTI client is in degraded mode."""

    pass


class GTIMCPClient:
    def __init__(
        self,
        repo: SQLiteThreatRepository,
        api_key: str = "",
        base_url: str = "https://www.virustotal.com/api/v3",
    ):
        self.repo = repo
        self.api_key = api_key
        self.base_url = base_url
        self.consecutive_failures = 0
        self.state = "CLOSED"  # CLOSED, OPEN (degraded), HALF-OPEN
        self.last_state_change = 0.0
        self.cooldown = 60.0  # seconds
        self.successful_retries = 0

    def is_degraded(self) -> bool:
        """Checks if the client is currently in degraded (OPEN) mode."""
        if self.state == "OPEN":
            if time.time() - self.last_state_change > self.cooldown:
                # Cooldown period has passed. Move to HALF-OPEN to test service.
                self.state = "HALF-OPEN"
                logger.info("GTI MCP Client moving from OPEN (degraded) to HALF-OPEN")
                return False
            return True
        return False

    async def queryIOC(
        self, indicator: str, indicator_type: IndicatorType
    ) -> GTIResponse:
        """
        Queries the threat intelligence for an indicator with caching, timeout,
        and circuit breaker logic.
        """
        # 1. Check local SQLite cache first.
        cached = await self.repo.get_cached_gti_response(
            indicator, indicator_type.value
        )
        if cached:
            logger.debug(f"GTI Cache hit for indicator: {indicator}")
            return GTIResponse.model_validate(cached)

        # 2. Check circuit breaker state (only for live queries).
        if self.is_degraded():
            raise GTIDegradedError("GTI MCP Client is in degraded mode.")

        # 3. Perform external API query with 5-second timeout.
        try:
            # Query inside wait_for to enforce timeout.
            response_dict = await asyncio.wait_for(
                self._execute_api_query(indicator, indicator_type), timeout=5.0
            )

            # Successful query.
            self.consecutive_failures = 0
            if self.state == "HALF-OPEN":
                self.successful_retries += 1
                if self.successful_retries >= 3:
                    self.state = "CLOSED"
                    self.successful_retries = 0
                    logger.info("GTI MCP Client restored to CLOSED (normal) mode.")

            # Cache the response.
            await self.repo.cache_gti_response(
                indicator, indicator_type.value, response_dict
            )
            return GTIResponse.model_validate(response_dict)

        except ValueError:
            # Unsupported indicator_type - propagate immediately without recording failure.
            raise
        except asyncio.TimeoutError as e:
            logger.warning(f"GTI query timeout for indicator: {indicator}")
            self._handle_failure()
            raise e
        except Exception as e:
            logger.warning(f"GTI query failed: {str(e)}")
            self._handle_failure()
            raise e

    def _handle_failure(self) -> None:
        if self.state == "HALF-OPEN":
            # Any failure in HALF-OPEN resets to OPEN.
            self.state = "OPEN"
            self.last_state_change = time.time()
            self.successful_retries = 0
            logger.warning("GTI MCP Client failed in HALF-OPEN state. Reset to OPEN.")
        else:
            self.consecutive_failures += 1
            if self.consecutive_failures >= 5:
                self.state = "OPEN"
                self.last_state_change = time.time()
                self.successful_retries = 0
                logger.error(
                    "GTI MCP Client reached 5 consecutive failures. Switching to OPEN (degraded) mode."
                )

    async def _execute_api_query(
        self, indicator: str, indicator_type: IndicatorType
    ) -> Dict[str, Any]:
        """Performs actual HTTP request to VirusTotal API."""
        headers = {
            "x-apikey": self.api_key,
            "accept": "application/json",
        }

        # Determine path based on indicator type.
        if indicator_type == IndicatorType.IP_ADDRESS:
            url = f"{self.base_url}/ip_addresses/{indicator}"
        elif indicator_type == IndicatorType.DOMAIN:
            url = f"{self.base_url}/domains/{indicator}"
        elif indicator_type == IndicatorType.URL:
            import base64

            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            url = f"{self.base_url}/urls/{url_id}"
        elif indicator_type == IndicatorType.FILE_HASH:
            url = f"{self.base_url}/files/{indicator}"
        else:
            raise ValueError(f"Unsupported indicator type: {indicator_type}")

        # Execute with retries & exponential backoff for 429
        retries = 0
        backoff = 0.1  # 100ms starting backoff
        max_retries = 3

        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 429:
                            if retries < max_retries:
                                retries += 1
                                logger.info(
                                    f"GTI hit rate limit. Backing off for {backoff}s (retry {retries}/{max_retries})"
                                )
                                await asyncio.sleep(backoff)
                                backoff *= 2
                                continue
                            else:
                                raise aiohttp.ClientResponseError(
                                    resp.request_info,
                                    resp.history,
                                    status=resp.status,
                                    message="Rate limit exceeded and retries exhausted",
                                    headers=resp.headers,
                                )

                        resp.raise_for_status()
                        data = await resp.json()
                        return self._parse_vt_response(indicator, data)
                except aiohttp.ClientError as e:
                    # Don't retry for other client errors, just raise.
                    raise e

    def _parse_vt_response(
        self, indicator: str, vt_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Parses VirusTotal API JSON response into a dict matching GTIResponse fields."""
        attributes = vt_data.get("data", {}).get("attributes", {})
        last_stats = attributes.get("last_analysis_stats", {})

        malicious = last_stats.get("malicious", 0)
        suspicious = last_stats.get("suspicious", 0)
        harmless = last_stats.get("harmless", 0)
        undetected = last_stats.get("undetected", 0)

        total = malicious + suspicious + harmless + undetected
        detection_rate = (
            ((malicious + suspicious) / total * 100.0) if total > 0 else 0.0
        )

        is_malicious = (
            malicious + suspicious
        ) > 0  # Heuristic including suspicious detections

        # Extract threat categories from engine results
        threat_categories = set()
        analysis_results = attributes.get("last_analysis_results", {})
        for engine, result in analysis_results.items():
            category = result.get("category")
            if category in ("malicious", "suspicious"):
                result_str = result.get("result")
                if result_str:
                    threat_categories.add(result_str.lower())

        categories_list = sorted(list(threat_categories))[:5]

        # Related campaigns
        related_campaigns = []
        tags = attributes.get("tags", [])
        for tag in tags:
            if "campaign" in tag or tag.startswith("c2-"):
                related_campaigns.append(tag)

        # Confidence
        confidence = (malicious / total) if total > 0 else 0.0

        # Last analysis date
        last_analysis_date_unix = attributes.get("last_analysis_date")
        last_analysis_date = None
        if last_analysis_date_unix:
            from datetime import datetime, timezone

            last_analysis_date = datetime.fromtimestamp(
                last_analysis_date_unix, tz=timezone.utc
            ).isoformat()

        return {
            "indicator": indicator,
            "is_malicious": is_malicious,
            "threat_categories": categories_list,
            "detection_rate": detection_rate,
            "last_analysis_date": last_analysis_date,
            "related_campaigns": related_campaigns,
            "confidence": confidence,
        }

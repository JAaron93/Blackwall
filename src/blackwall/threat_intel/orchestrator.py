"""Threat Intelligence Orchestrator.

Orchestrates multi-provider threat intelligence queries across primary (AlienVault OTX)
and supplementary feeds (AbuseIPDB, abuse.ch) with < 1ms SQLite cache short-circuiting,
circuit breaker protection, and highest-confidence score aggregation.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, List, Optional, Set

from blackwall.threat_intel.abusech import AbuseChProvider
from blackwall.threat_intel.abuseipdb import AbuseIPDBProvider
from blackwall.threat_intel.circuit_breaker import CircuitBreakerProvider
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelProvider,
    ThreatIntelResponse,
)
from blackwall.threat_intel.otx import AlienVaultOTXProvider

logger = logging.getLogger("blackwall.threat_intel.orchestrator")


def _wrap_provider(
    provider: ThreatIntelProvider, timeout: float
) -> ThreatIntelProvider:
    """Wraps provider in CircuitBreakerProvider if not already wrapped."""
    if isinstance(provider, CircuitBreakerProvider):
        return provider
    return CircuitBreakerProvider(provider, timeout=timeout)


class ThreatIntelOrchestrator:
    """Multi-provider Threat Intelligence Orchestrator with cache-first resolution."""

    def __init__(
        self,
        repository: Optional[Any] = None,
        primary_provider: Optional[ThreatIntelProvider] = None,
        secondary_providers: Optional[List[ThreatIntelProvider]] = None,
        cache_enabled: bool = True,
        timeout: float = 3.0,
        wrap_circuit_breaker: bool = True,
    ) -> None:
        self.repository = repository
        self.cache_enabled = cache_enabled
        self.timeout = timeout

        if primary_provider is not None:
            self.primary_provider = (
                _wrap_provider(primary_provider, timeout)
                if wrap_circuit_breaker
                else primary_provider
            )
        else:
            otx = AlienVaultOTXProvider()
            self.primary_provider = (
                _wrap_provider(otx, timeout)
                if wrap_circuit_breaker
                else otx
            )

        if secondary_providers is not None:
            self.secondary_providers: List[ThreatIntelProvider] = [
                _wrap_provider(p, timeout) if wrap_circuit_breaker else p
                for p in secondary_providers
            ]
        else:
            self.secondary_providers = []
            # Automatically register optional providers if available
            try:
                abuseipdb = AbuseIPDBProvider()
                if abuseipdb.api_key:
                    self.secondary_providers.append(
                        _wrap_provider(abuseipdb, timeout)
                        if wrap_circuit_breaker
                        else abuseipdb
                    )
            except Exception as e:
                logger.debug("Failed initializing AbuseIPDB: %s", e)

            try:
                abusech = AbuseChProvider()
                self.secondary_providers.append(
                    _wrap_provider(abusech, timeout)
                    if wrap_circuit_breaker
                    else abusech
                )
            except Exception as e:
                logger.debug("Failed initializing AbuseChProvider: %s", e)

    def get_providers(self) -> List[ThreatIntelProvider]:
        """Return list of all registered providers (primary + secondaries)."""
        return [self.primary_provider] + list(self.secondary_providers)

    def get_provider(self, name: str) -> Optional[ThreatIntelProvider]:
        """Look up provider by name (case-insensitive)."""
        target = name.strip().lower()
        for p in self.get_providers():
            p_name = p.name.lower()
            if p_name == target:
                return p
        return None

    async def is_healthy(self) -> bool:
        """Check overall health of registered threat intelligence providers."""
        try:
            if await self.primary_provider.is_healthy():
                return True
        except Exception:
            pass

        for sec in self.secondary_providers:
            try:
                if await sec.is_healthy():
                    return True
            except Exception:
                pass
        return False

    async def lookup(
        self,
        indicator: str,
        indicator_type: ThreatIndicatorType,
        timeout: Optional[float] = None,
        no_cache: bool = False,
        provider: Optional[str] = None,
    ) -> ThreatIntelResponse:
        """Looks up threat intelligence for an indicator across providers with caching."""
        indicator = indicator.strip()
        if not indicator:
            raise ValueError("Indicator cannot be empty")
        if indicator_type == ThreatIndicatorType.FILE_HASH:
            indicator = indicator.lower()

        effective_timeout = timeout if timeout is not None else self.timeout

        # Step 1: Determine applicable providers and normalize cache scope

        if provider:
            target_provider = self.get_provider(provider)
            if not target_provider:
                raise ValueError(f"Unknown threat intel provider: {provider}")
            if indicator_type not in target_provider.supported_indicators:
                raise ValueError(
                    f"Provider {provider} does not support indicator type {indicator_type}"
                )
            cache_provider = target_provider.name
            active_providers = [target_provider]
        else:
            cache_provider = "aggregate"
            active_providers = []
            if indicator_type in self.primary_provider.supported_indicators:
                active_providers.append(self.primary_provider)
            for sec in self.secondary_providers:
                if indicator_type in sec.supported_indicators:
                    active_providers.append(sec)

            if not active_providers:
                raise ValueError(
                    f"No configured provider supports indicator type {indicator_type}"
                )

        # Step 2: Cache check (< 1ms fast path)
        if self.cache_enabled and not no_cache and self.repository is not None:
            ind_type_str = (
                indicator_type.value
                if hasattr(indicator_type, "value")
                else str(indicator_type)
            )
            cached_resp = await self.repository.get_cached_threat_intel(
                indicator, ind_type_str, provider=cache_provider
            )
            if cached_resp is not None:
                logger.debug(
                    "Threat intel cache hit for %s (provider=%s)",
                    indicator,
                    cache_provider,
                )
                return cached_resp

        # Step 3: Query providers concurrently

        tasks = [
            p.lookup(indicator, indicator_type, timeout=effective_timeout)
            for p in active_providers
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_responses: List[ThreatIntelResponse] = []
        for r in results:
            if isinstance(r, ThreatIntelResponse):
                valid_responses.append(r)
            elif isinstance(r, Exception):
                logger.warning(
                    "Threat intel provider lookup failed for %s: %s", indicator, r
                )

        # Step 4: Multi-source score aggregation
        non_error_responses = [r for r in valid_responses if not r.error]
        if not non_error_responses:
            error_details = "; ".join(
                [r.error for r in valid_responses if r.error]
            ) or "All threat intelligence providers failed or timed out"
            logger.warning(
                "Threat intel resolution failed for %s: %s", indicator, error_details
            )
            # Propagate error response; DO NOT cache this outage response as benign!
            return ThreatIntelResponse(
                indicator=indicator,
                indicator_type=indicator_type,
                is_malicious=False,
                risk_score=0.0,
                provider_name=cache_provider,
                error=error_details,
                cached=False,
            )

        max_risk = max(r.risk_score for r in non_error_responses)
        is_malicious = any(r.is_malicious for r in non_error_responses) or (
            max_risk >= 0.25
        )
        detection_count = max(r.detection_count for r in non_error_responses)
        total_engines = max(r.total_engines for r in non_error_responses)
        pulse_count = max(r.pulse_count for r in non_error_responses)

        categories: Set[str] = set()
        malware_families: Set[str] = set()
        references: List[str] = []
        provider_names: Set[str] = set()

        for r in non_error_responses:
            categories.update(r.threat_categories)
            malware_families.update(r.malware_families)
            for ref in r.references:
                if ref and ref not in references:
                    references.append(ref)
            if r.provider_name:
                provider_names.add(r.provider_name)

        if provider:
            provider_name = provider
        elif len(provider_names) == 1:
            provider_name = next(iter(provider_names))
        else:
            highest_provider = max(
                non_error_responses, key=lambda x: x.risk_score
            ).provider_name
            provider_name = highest_provider or ", ".join(sorted(provider_names))

        aggregated = ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=is_malicious,
            risk_score=max_risk,
            detection_count=detection_count,
            total_engines=total_engines,
            threat_categories=sorted(list(categories)),
            malware_families=sorted(list(malware_families)),
            pulse_count=pulse_count,
            references=references[:10],
            provider_name=provider_name,
            cached=False,
        )

        # Step 5: Cache resolved results asynchronously (ONLY for valid, non-outage responses)
        if (
            self.cache_enabled
            and not no_cache
            and self.repository is not None
            and not aggregated.error
        ):
            ttl = 21600.0 if aggregated.is_malicious else 86400.0
            try:
                await self.repository.cache_threat_intel(
                    aggregated, ttl_seconds=ttl, provider=cache_provider
                )
            except Exception as e:
                logger.warning(
                    "Failed caching threat intel response for %s: %s", indicator, e
                )

        return aggregated

    async def clear_cache(self, expired_only: bool = False) -> int:
        """Evicts cached threat intel records."""
        if self.repository is None:
            return 0
        if expired_only:
            return await self.repository.prune_expired_threat_intel()
        else:
            await self.repository.initialize()
            async with self.repository.pool.connection() as conn:
                cursor = await conn.execute("DELETE FROM threat_intel_cache")
                return cursor.rowcount


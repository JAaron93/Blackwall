from __future__ import annotations

import os
import tempfile
import time
from typing import AsyncGenerator
import pytest
import pytest_asyncio

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)
from blackwall.threat_intel.orchestrator import ThreatIntelOrchestrator


class MockProvider:
    def __init__(
        self,
        name: str,
        supported_indicators: set[ThreatIndicatorType],
        default_response: ThreatIntelResponse | None = None,
    ) -> None:
        self.name = name
        self.supported_indicators = supported_indicators
        self.default_response = default_response
        self.call_count = 0

    async def lookup(
        self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float = 3.0
    ) -> ThreatIntelResponse:
        self.call_count += 1
        if self.default_response:
            return self.default_response
        return ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=False,
            risk_score=0.0,
            provider_name=self.name,
        )

    async def is_healthy(self) -> bool:
        return True

    def get_remaining_budget(self) -> int:
        return 5000


@pytest_asyncio.fixture
async def temp_repo() -> AsyncGenerator[SQLiteThreatRepository, None]:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    repo = SQLiteThreatRepository(db_path=db_path)
    await repo.initialize()
    yield repo
    await repo.close()
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.mark.asyncio
async def test_orchestrator_cache_first_short_circuit(
    temp_repo: SQLiteThreatRepository,
) -> None:
    primary = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4, ThreatIndicatorType.DOMAIN},
    )
    orchestrator = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=primary,
        secondary_providers=[],
    )

    # Pre-populate cache
    cached_payload = ThreatIntelResponse(
        indicator="198.51.100.99",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=True,
        risk_score=0.95,
        malware_families=["Lumma"],
        provider_name="otx",
    )
    await temp_repo.cache_threat_intel(cached_payload)

    # Lookup should return cached result in < 1ms without hitting provider
    start = time.monotonic()
    result = await orchestrator.lookup("198.51.100.99", ThreatIndicatorType.IPV4)
    elapsed_ms = (time.monotonic() - start) * 1000

    assert result.indicator == "198.51.100.99"
    assert result.is_malicious is True
    assert result.risk_score == 0.95
    assert result.cached is True
    assert "Lumma" in result.malware_families
    assert primary.call_count == 0
    assert elapsed_ms < 10.0  # Fast path check


@pytest.mark.asyncio
async def test_orchestrator_cache_miss_populates_cache(
    temp_repo: SQLiteThreatRepository,
) -> None:
    primary_resp = ThreatIntelResponse(
        indicator="malicious-sample.net",
        indicator_type=ThreatIndicatorType.DOMAIN,
        is_malicious=True,
        risk_score=0.88,
        malware_families=["RedLine"],
        provider_name="otx",
    )
    primary = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.DOMAIN},
        default_response=primary_resp,
    )
    orchestrator = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=primary,
        secondary_providers=[],
    )

    # 1. First lookup is a cache miss, calls provider and caches result
    res1 = await orchestrator.lookup("malicious-sample.net", ThreatIndicatorType.DOMAIN)
    assert res1.indicator == "malicious-sample.net"
    assert res1.cached is False
    assert primary.call_count == 1

    # 2. Second lookup hits cache directly
    res2 = await orchestrator.lookup("malicious-sample.net", ThreatIndicatorType.DOMAIN)
    assert res2.indicator == "malicious-sample.net"
    assert res2.cached is True
    assert res2.risk_score == 0.88
    assert "RedLine" in res2.malware_families
    assert primary.call_count == 1  # Provider not called second time!


@pytest.mark.asyncio
async def test_orchestrator_multi_source_score_aggregation() -> None:
    # Primary reports low risk
    primary_resp = ThreatIntelResponse(
        indicator="198.51.100.5",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=False,
        risk_score=0.10,
        threat_categories=["scanner"],
        provider_name="otx",
    )
    primary = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4},
        default_response=primary_resp,
    )

    # Secondary AbuseIPDB reports moderate risk
    sec1_resp = ThreatIntelResponse(
        indicator="198.51.100.5",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=True,
        risk_score=0.60,
        detection_count=15,
        threat_categories=["ssh-bruteforce"],
        provider_name="abuseipdb",
    )
    sec1 = MockProvider(
        name="abuseipdb",
        supported_indicators={ThreatIndicatorType.IPV4},
        default_response=sec1_resp,
    )

    # Secondary AbuseCh reports critical malware risk
    sec2_resp = ThreatIntelResponse(
        indicator="198.51.100.5",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=True,
        risk_score=0.95,
        malware_families=["Cobalt Strike"],
        threat_categories=["c2"],
        references=["https://threatfox.abuse.ch/ioc/123/"],
        provider_name="abusech",
    )
    sec2 = MockProvider(
        name="abusech",
        supported_indicators={ThreatIndicatorType.IPV4},
        default_response=sec2_resp,
    )

    orchestrator = ThreatIntelOrchestrator(
        repository=None,
        primary_provider=primary,
        secondary_providers=[sec1, sec2],
        cache_enabled=False,
    )

    aggregated = await orchestrator.lookup("198.51.100.5", ThreatIndicatorType.IPV4)

    # Highest confidence score selected
    assert aggregated.risk_score == 0.95
    assert aggregated.is_malicious is True
    assert "Cobalt Strike" in aggregated.malware_families
    assert "c2" in aggregated.threat_categories
    assert "ssh-bruteforce" in aggregated.threat_categories
    assert "scanner" in aggregated.threat_categories
    assert "https://threatfox.abuse.ch/ioc/123/" in aggregated.references


@pytest.mark.asyncio
async def test_orchestrator_indicator_type_routing() -> None:
    otx = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4, ThreatIndicatorType.DOMAIN},
    )
    abuseipdb = MockProvider(
        name="abuseipdb",
        supported_indicators={ThreatIndicatorType.IPV4},  # No DOMAIN support
    )
    abusech = MockProvider(
        name="abusech",
        supported_indicators={ThreatIndicatorType.IPV4, ThreatIndicatorType.DOMAIN},
    )

    orchestrator = ThreatIntelOrchestrator(
        primary_provider=otx,
        secondary_providers=[abuseipdb, abusech],
        cache_enabled=False,
    )

    # Looking up DOMAIN must skip abuseipdb
    await orchestrator.lookup("test-c2.org", ThreatIndicatorType.DOMAIN)
    assert otx.call_count == 1
    assert abusech.call_count == 1
    assert abuseipdb.call_count == 0


@pytest.mark.asyncio
async def test_orchestrator_specific_provider_lookup() -> None:
    otx = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4},
    )
    abuseipdb = MockProvider(
        name="abuseipdb",
        supported_indicators={ThreatIndicatorType.IPV4},
    )

    orchestrator = ThreatIntelOrchestrator(
        primary_provider=otx,
        secondary_providers=[abuseipdb],
        cache_enabled=False,
    )

    resp = await orchestrator.lookup(
        "198.51.100.10", ThreatIndicatorType.IPV4, provider="abuseipdb"
    )
    assert otx.call_count == 0
    assert abuseipdb.call_count == 1
    assert resp.provider_name == "abuseipdb"


@pytest.mark.asyncio
async def test_orchestrator_resilience_on_failing_provider() -> None:
    class FailingProvider:
        name: str = "broken"
        supported_indicators: set[ThreatIndicatorType] = {ThreatIndicatorType.IPV4}

        async def lookup(
            self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float = 3.0
        ) -> ThreatIntelResponse:
            raise ConnectionError("Service unreachable")

        async def is_healthy(self) -> bool:
            return False

        def get_remaining_budget(self) -> int:
            return 0

    healthy = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4},
        default_response=ThreatIntelResponse(
            indicator="1.2.3.4",
            indicator_type=ThreatIndicatorType.IPV4,
            is_malicious=False,
            risk_score=0.0,
            provider_name="otx",
        ),
    )

    orchestrator = ThreatIntelOrchestrator(
        primary_provider=healthy,
        secondary_providers=[FailingProvider()],  # type: ignore
        cache_enabled=False,
    )

    # Lookup should not raise exception; healthy provider resolves query
    resp = await orchestrator.lookup("1.2.3.4", ThreatIndicatorType.IPV4)
    assert resp.indicator == "1.2.3.4"
    assert resp.is_malicious is False
    assert resp.provider_name == "otx"


@pytest.mark.asyncio
async def test_orchestrator_clear_cache(temp_repo: SQLiteThreatRepository) -> None:
    orchestrator = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=MockProvider(
            name="otx", supported_indicators={ThreatIndicatorType.IPV4}
        ),
    )

    resp = ThreatIntelResponse(
        indicator="10.0.0.1",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=False,
        provider_name="otx",
    )
    await temp_repo.cache_threat_intel(resp)

    # Verify present
    cached = await temp_repo.get_cached_threat_intel("10.0.0.1", "IPV4")
    assert cached is not None

    # Clear all cache
    deleted = await orchestrator.clear_cache(expired_only=False)
    assert deleted >= 1

    cleared = await temp_repo.get_cached_threat_intel("10.0.0.1", "IPV4")
    assert cleared is None

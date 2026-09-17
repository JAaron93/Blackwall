from __future__ import annotations

import os
import tempfile
import time
from typing import AsyncGenerator
from unittest.mock import patch
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
        provider_name="aggregate",
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



@pytest.mark.asyncio
async def test_orchestrator_does_not_cache_outages(
    temp_repo: SQLiteThreatRepository,
) -> None:
    class AlwaysFailingProvider:
        name = "otx"
        supported_indicators = {ThreatIndicatorType.IPV4}

        async def lookup(
            self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float = 3.0
        ) -> ThreatIntelResponse:
            raise ConnectionError("Service down")

        async def is_healthy(self) -> bool:
            return False

        def get_remaining_budget(self) -> int:
            return 0

    orchestrator = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=AlwaysFailingProvider(),  # type: ignore
        secondary_providers=[],
        cache_enabled=True,
    )

    resp = await orchestrator.lookup("198.51.100.88", ThreatIndicatorType.IPV4)
    assert resp.error is not None

    # Verify that outage was NOT cached as benign
    cached = await temp_repo.get_cached_threat_intel(
        "198.51.100.88", ThreatIndicatorType.IPV4.value, provider="aggregate"
    )
    assert cached is None


@pytest.mark.asyncio
async def test_orchestrator_cache_scoping_isolation(
    temp_repo: SQLiteThreatRepository,
) -> None:
    otx_resp = ThreatIntelResponse(
        indicator="198.51.100.77",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=True,
        risk_score=0.9,
        provider_name="otx",
    )
    otx = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4},
        default_response=otx_resp,
    )
    abuseipdb = MockProvider(
        name="abuseipdb",
        supported_indicators={ThreatIndicatorType.IPV4},
        default_response=ThreatIntelResponse(
            indicator="198.51.100.77",
            indicator_type=ThreatIndicatorType.IPV4,
            is_malicious=False,
            risk_score=0.0,
            provider_name="abuseipdb",
        ),
    )

    orchestrator = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=otx,
        secondary_providers=[abuseipdb],
        cache_enabled=True,
    )

    # 1. Generic multi-provider lookup caches under "aggregate"
    agg = await orchestrator.lookup("198.51.100.77", ThreatIndicatorType.IPV4)
    assert agg.risk_score == 0.9
    assert otx.call_count == 1
    assert abuseipdb.call_count == 1

    # 2. Explicit lookup for "abuseipdb" should NOT return the generic "aggregate" cache
    # It queries the abuseipdb provider directly
    single = await orchestrator.lookup(
        "198.51.100.77", ThreatIndicatorType.IPV4, provider="abuseipdb"
    )
    assert single.risk_score == 0.0
    assert single.provider_name == "abuseipdb"
    assert abuseipdb.call_count == 2


@pytest.mark.asyncio
async def test_orchestrator_provider_name_case_normalization_in_cache(
    temp_repo: SQLiteThreatRepository,
) -> None:
    otx = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4},
        default_response=ThreatIntelResponse(
            indicator="198.51.100.55",
            indicator_type=ThreatIndicatorType.IPV4,
            is_malicious=False,
            risk_score=0.0,
            provider_name="otx",
        ),
    )
    orchestrator = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=otx,
        cache_enabled=True,
    )

    # First lookup with uppercase 'OTX'
    res1 = await orchestrator.lookup(
        "198.51.100.55", ThreatIndicatorType.IPV4, provider="OTX"
    )
    assert res1.cached is False
    assert otx.call_count == 1

    # Second lookup with lowercase 'otx' hits normalized cache
    res2 = await orchestrator.lookup(
        "198.51.100.55", ThreatIndicatorType.IPV4, provider="otx"
    )
    assert res2.cached is True
    assert otx.call_count == 1


@pytest.mark.asyncio
async def test_orchestrator_provider_name_identical_on_cache_miss_and_hit(
    temp_repo: SQLiteThreatRepository,
) -> None:
    otx = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4},
        default_response=ThreatIntelResponse(
            indicator="198.51.100.60",
            indicator_type=ThreatIndicatorType.IPV4,
            is_malicious=True,
            risk_score=0.9,
            provider_name="otx",
        ),
    )
    orchestrator = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=otx,
        secondary_providers=[],
        cache_enabled=True,
    )

    # First lookup (cache miss)
    miss_res = await orchestrator.lookup("198.51.100.60", ThreatIndicatorType.IPV4)
    assert miss_res.cached is False
    assert miss_res.provider_name == "otx"

    # Second lookup (cache hit)
    hit_res = await orchestrator.lookup("198.51.100.60", ThreatIndicatorType.IPV4)
    assert hit_res.cached is True
    # provider_name must remain "otx" on cache hit, NOT mutate to "aggregate"
    assert hit_res.provider_name == "otx"
    assert hit_res.risk_score == miss_res.risk_score
    assert hit_res.is_malicious == miss_res.is_malicious


@pytest.mark.asyncio
async def test_orchestrator_indicator_normalization_and_empty_check(
    temp_repo: SQLiteThreatRepository,
) -> None:
    otx = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4, ThreatIndicatorType.FILE_HASH},
        default_response=ThreatIntelResponse(
            indicator="198.51.100.65",
            indicator_type=ThreatIndicatorType.IPV4,
            is_malicious=False,
            risk_score=0.0,
            provider_name="otx",
        ),
    )
    orchestrator = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=otx,
        secondary_providers=[],
        cache_enabled=True,
    )

    # Whitespace in IP is stripped
    res = await orchestrator.lookup("  198.51.100.65  \n", ThreatIndicatorType.IPV4)
    assert res.indicator == "198.51.100.65"

    # Empty indicator raises ValueError
    with pytest.raises(ValueError, match="Indicator cannot be empty"):
        await orchestrator.lookup("   \t  ", ThreatIndicatorType.IPV4)


@pytest.mark.asyncio
async def test_orchestrator_persistent_cache_metrics_across_instances(
    temp_repo: SQLiteThreatRepository,
) -> None:
    """Verify that cache hits and misses are persisted and retrievable across separate orchestrator instances."""
    otx = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4},
        default_response=ThreatIntelResponse(
            indicator="198.51.100.99",
            indicator_type=ThreatIndicatorType.IPV4,
            is_malicious=False,
            risk_score=0.0,
            provider_name="otx",
        ),
    )

    # First orchestrator instance: 1 miss, 1 hit
    orch1 = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=otx,
        secondary_providers=[],
        cache_enabled=True,
    )
    # Miss
    resp1 = await orch1.lookup("198.51.100.99", ThreatIndicatorType.IPV4)
    assert resp1.cached is False
    # Hit
    resp2 = await orch1.lookup("198.51.100.99", ThreatIndicatorType.IPV4)
    assert resp2.cached is True

    # Second fresh orchestrator instance accessing same repository:
    # Must retrieve persisted cumulative metrics!
    orch2 = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=otx,
        secondary_providers=[],
        cache_enabled=True,
    )
    stats = await orch2.get_cache_stats()
    assert stats["hits"] >= 1
    assert stats["misses"] >= 1
    assert stats["total_entries"] >= 1


@pytest.mark.asyncio
async def test_orchestrator_harpoon_provider_discovery_and_registration() -> None:
    """Verify that HarpoonBridge is discoverable via get_provider('harpoon')."""
    orch = ThreatIntelOrchestrator(
        primary_provider=MockProvider(name="otx", supported_indicators={ThreatIndicatorType.IPV4}),
        secondary_providers=[],
        cache_enabled=False,
    )
    provider = orch.get_provider("harpoon")
    assert provider is not None
    assert provider.name == "harpoon"


@pytest.mark.asyncio
async def test_orchestrator_harpoon_not_in_default_secondary_providers() -> None:
    """Verify Harpoon is not in default secondary feeds, preventing duplicate OTX requests."""
    with patch("blackwall.threat_intel.harpoon.HarpoonBridge.is_available", return_value=True):
        orch = ThreatIntelOrchestrator(
            primary_provider=MockProvider(name="otx", supported_indicators={ThreatIndicatorType.IPV4}),
            cache_enabled=False,
        )
        # Harpoon should NOT be in secondary_providers to avoid duplicate queries on aggregate miss
        secondary_names = [p.name.lower() for p in orch.secondary_providers]
        assert "harpoon" not in secondary_names

        # But it should be discoverable for explicit lookup or inspection
        assert orch.get_provider("harpoon") is not None
        all_provs = orch.get_providers(include_on_demand=True)
        assert any(p.name.lower() == "harpoon" for p in all_provs)


@pytest.mark.asyncio
async def test_orchestrator_primary_harpoon_override_via_env() -> None:
    """Verify Harpoon can replace OTX as primary provider via environment variable."""
    with patch.dict(os.environ, {"BW_THREAT_INTEL_PRIMARY": "harpoon"}):
        orch = ThreatIntelOrchestrator(cache_enabled=False)
        assert orch.primary_provider.name.lower() == "harpoon"


@pytest.mark.asyncio
async def test_orchestrator_cache_metrics_batch_flush(temp_repo: SQLiteThreatRepository) -> None:
    """Verify cache metrics are queued and batched without blocking lookup returns."""
    otx = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4},
        default_response=ThreatIntelResponse(
            indicator="198.51.100.55",
            indicator_type=ThreatIndicatorType.IPV4,
            is_malicious=False,
            risk_score=0.0,
            provider_name="otx",
        ),
    )
    orch = ThreatIntelOrchestrator(
        repository=temp_repo,
        primary_provider=otx,
        secondary_providers=[],
        cache_enabled=True,
    )

    # 1 Miss
    resp1 = await orch.lookup("198.51.100.55", ThreatIndicatorType.IPV4)
    assert resp1.cached is False

    # 3 Hits
    for _ in range(3):
        resp_hit = await orch.lookup("198.51.100.55", ThreatIndicatorType.IPV4)
        assert resp_hit.cached is True

    # Flush batch to SQLite
    await orch.flush_metrics()

    stats = await orch.get_cache_stats()
    assert stats["hits"] >= 3
    assert stats["misses"] >= 1


@pytest.mark.asyncio
async def test_orchestrator_harpoon_primary_pulse_lookup_delegates_to_fallback() -> None:
    """Verify get_pulse works when Harpoon is primary by delegating to OTX fallback."""
    from unittest.mock import AsyncMock
    from blackwall.threat_intel.harpoon import HarpoonBridge

    mock_otx = MockProvider(
        name="otx",
        supported_indicators={ThreatIndicatorType.IPV4},
    )
    mock_otx.get_pulse = AsyncMock(return_value={"id": "pulse-999", "name": "Test Pulse"})

    bridge = HarpoonBridge(fallback_provider=mock_otx)
    orch = ThreatIntelOrchestrator(
        primary_provider=bridge,
        cache_enabled=False,
    )

    pulse = await orch.get_pulse("pulse-999")
    assert pulse["id"] == "pulse-999"
    assert pulse["name"] == "Test Pulse"
    mock_otx.get_pulse.assert_called_once_with("pulse-999", timeout=3.0)






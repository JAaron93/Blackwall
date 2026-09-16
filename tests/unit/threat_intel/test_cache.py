from __future__ import annotations

import os
import tempfile
import time
from typing import AsyncGenerator

import pytest
import pytest_asyncio

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.threat_intel.models import ThreatIndicatorType, ThreatIntelResponse


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
async def test_threat_intel_cache_roundtrip(
    temp_repo: SQLiteThreatRepository,
) -> None:
    resp = ThreatIntelResponse(
        indicator="198.51.100.25",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=True,
        risk_score=0.9,
        detection_count=5,
        threat_categories=["c2"],
        malware_families=["Cobalt Strike"],
        pulse_count=3,
        provider_name="otx",
    )

    # Cache response
    await temp_repo.cache_threat_intel(resp)

    # Retrieve response
    cached = await temp_repo.get_cached_threat_intel(
        "198.51.100.25", ThreatIndicatorType.IPV4.value, provider="otx"
    )
    assert cached is not None
    assert cached.indicator == "198.51.100.25"
    assert cached.is_malicious is True
    assert cached.risk_score == 0.9
    assert cached.malware_families == ["Cobalt Strike"]
    assert cached.cached is True
    assert cached.provider_name == "otx"

    # Also test query without provider
    cached_any = await temp_repo.get_cached_threat_intel(
        "198.51.100.25", ThreatIndicatorType.IPV4.value
    )
    assert cached_any is not None
    assert cached_any.indicator == "198.51.100.25"


@pytest.mark.asyncio
async def test_threat_intel_cache_ttl_and_pruning(
    temp_repo: SQLiteThreatRepository,
) -> None:
    resp = ThreatIntelResponse(
        indicator="temporary.bad",
        indicator_type=ThreatIndicatorType.DOMAIN,
        is_malicious=False,
        risk_score=0.0,
        provider_name="otx",
    )

    # Cache with very short TTL of 0.05 seconds
    await temp_repo.cache_threat_intel(resp, ttl_seconds=0.05)

    # Immediately available
    cached = await temp_repo.get_cached_threat_intel(
        "temporary.bad", ThreatIndicatorType.DOMAIN.value
    )
    assert cached is not None

    # Wait for expiration
    time.sleep(0.08)

    # Should return None after expiration
    expired = await temp_repo.get_cached_threat_intel(
        "temporary.bad", ThreatIndicatorType.DOMAIN.value
    )
    assert expired is None

    # Prune should delete expired row
    deleted = await temp_repo.prune_expired_threat_intel()
    assert deleted >= 1


@pytest.mark.asyncio
async def test_threat_intel_cache_sub_millisecond_sla(
    temp_repo: SQLiteThreatRepository,
) -> None:
    resp = ThreatIntelResponse(
        indicator="fast.lookup.com",
        indicator_type=ThreatIndicatorType.DOMAIN,
        is_malicious=False,
        risk_score=0.0,
        provider_name="otx",
    )
    await temp_repo.cache_threat_intel(resp)

    # Warmup
    for _ in range(5):
        await temp_repo.get_cached_threat_intel(
            "fast.lookup.com", ThreatIndicatorType.DOMAIN.value
        )

    # Benchmark 100 cache hits
    start = time.perf_counter()
    iterations = 100
    for _ in range(iterations):
        res = await temp_repo.get_cached_threat_intel(
            "fast.lookup.com", ThreatIndicatorType.DOMAIN.value
        )
        assert res is not None
    elapsed_ms = (time.perf_counter() - start) * 1000
    avg_latency_ms = elapsed_ms / iterations

    # Average latency must be < 1.0 ms
    assert avg_latency_ms < 1.0, f"Average cache hit latency {avg_latency_ms:.3f}ms exceeded 1.0ms SLA"

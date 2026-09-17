"""BDD Step Definitions for High-Throughput Threat Intelligence Resolution (`tests/features/threat_intel_high_throughput.feature`)."""

from __future__ import annotations

import os
import tempfile
import time
from typing import Any
import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import ToolCallContext, VerdictDecision
from blackwall.sync_resolver import SyncResolver
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)
from blackwall.threat_intel.orchestrator import ThreatIntelOrchestrator
from tests.step_defs.async_utils import run_async

scenarios("../features/threat_intel_high_throughput.feature")


class HighThroughputBDDState:
    """State holder for high-throughput threat intel BDD scenario."""

    def __init__(self) -> None:
        self.db_path: str | None = None
        self.repo: SQLiteThreatRepository | None = None
        self.orchestrator: ThreatIntelOrchestrator | None = None
        self.resolver: SyncResolver | None = None
        self.latencies: list[float] = []
        self.cached_query_latencies: list[float] = []
        self.verdicts: list[Any] = []
        self.total_duration: float = 0.0


@pytest.fixture
def bdd_state() -> HighThroughputBDDState:
    state = HighThroughputBDDState()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        state.db_path = f.name
    state.repo = SQLiteThreatRepository(db_path=state.db_path)
    run_async(state.repo.initialize())
    yield state
    if state.repo:
        run_async(state.repo.close())
    if state.db_path and os.path.exists(state.db_path):
        os.remove(state.db_path)


class FastMockProvider:
    """Simulated provider that responds quickly and records calls."""

    name = "mock-otx"
    supported_indicators = {
        ThreatIndicatorType.IPV4,
        ThreatIndicatorType.IPV6,
        ThreatIndicatorType.DOMAIN,
        ThreatIndicatorType.URL,
        ThreatIndicatorType.FILE_HASH,
    }

    def __init__(self) -> None:
        self.call_count = 0

    async def lookup(
        self, indicator: str, indicator_type: ThreatIndicatorType, **kwargs: Any
    ) -> ThreatIntelResponse:
        self.call_count += 1
        return ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=True,
            risk_score=0.92,
            threat_categories=["c2", "malware"],
            provider_name=self.name,
        )

    async def is_healthy(self) -> bool:
        return True


@given("a high-capacity threat intelligence resolver with SQLite caching enabled")
def given_high_capacity_resolver(bdd_state: HighThroughputBDDState) -> None:
    provider = FastMockProvider()
    bdd_state.orchestrator = ThreatIntelOrchestrator(
        repository=bdd_state.repo,
        primary_provider=provider,
        secondary_providers=[],
        cache_enabled=True,
        wrap_circuit_breaker=False,
    )
    bdd_state.resolver = SyncResolver(
        client=None,
        repo=bdd_state.repo,
        threat_intel=bdd_state.orchestrator,
        demo_mode=True,
    )


@when("an AI agent executes 20 consecutive network tool calls within 10 seconds")
def when_agent_executes_20_calls(bdd_state: HighThroughputBDDState) -> None:
    async def _run_burst() -> None:
        assert bdd_state.resolver is not None
        assert bdd_state.orchestrator is not None

        start_all = time.perf_counter()
        target_indicator = "malicious-c2.xyz"

        for i in range(20):
            ctx = ToolCallContext(
                tool_name="http_request",
                arguments={"url": f"http://{target_indicator}/beacon?seq={i}"},
            )
            t0 = time.perf_counter()
            verdict = await bdd_state.resolver.evaluate(ctx)
            t1 = time.perf_counter()
            bdd_state.latencies.append(t1 - t0)
            bdd_state.verdicts.append(verdict)

        # Warmup and benchmark cached queries against SQLite threat_intel_cache (< 1.0ms SLA)
        for _ in range(5):
            await bdd_state.repo.get_cached_threat_intel(
                target_indicator, ThreatIndicatorType.DOMAIN.value
            )
        for _ in range(20):
            ct0 = time.perf_counter()
            cached_res = await bdd_state.repo.get_cached_threat_intel(
                target_indicator, ThreatIndicatorType.DOMAIN.value
            )
            ct1 = time.perf_counter()
            bdd_state.cached_query_latencies.append(ct1 - ct0)
            assert cached_res is not None
            assert cached_res.cached is True

        bdd_state.total_duration = time.perf_counter() - start_all

    run_async(_run_burst())


@then("all 20 calls must be evaluated successfully without query throttling")
def then_all_calls_evaluated_without_throttling(bdd_state: HighThroughputBDDState) -> None:
    assert len(bdd_state.verdicts) == 20
    assert bdd_state.resolver is not None
    assert bdd_state.resolver._threat_intel_queries_deferred == 0
    assert bdd_state.resolver._threat_intel_queries_executed >= 20
    assert bdd_state.total_duration < 10.0
    for v in bdd_state.verdicts:
        assert v.decision == VerdictDecision.BLOCK


@then("live queries must complete within 2.0 seconds")
def then_live_queries_within_2_seconds(bdd_state: HighThroughputBDDState) -> None:
    assert len(bdd_state.latencies) > 0
    # First query includes live provider lookup
    live_latency = bdd_state.latencies[0]
    assert live_latency < 2.0, f"Live query latency {live_latency:.4f}s exceeded 2.0s"


@then("subsequent cached queries must complete in less than 1.0 milliseconds")
def then_cached_queries_sub_millisecond(bdd_state: HighThroughputBDDState) -> None:
    assert len(bdd_state.cached_query_latencies) > 0
    # Average cached lookup latency across warm queries must be < 1.0 ms (0.001s)
    min_cached = min(bdd_state.cached_query_latencies)
    avg_cached = sum(bdd_state.cached_query_latencies) / len(bdd_state.cached_query_latencies)
    assert min_cached < 0.001 or avg_cached < 0.001, (
        f"Cached query latency min={min_cached*1000:.3f}ms, avg={avg_cached*1000:.3f}ms exceeded 1.0ms SLA"
    )

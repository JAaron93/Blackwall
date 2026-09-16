"""BDD Step Definitions for Threat Intelligence Orchestration (`tests/features/threat_intel_orchestration.feature`)."""

from __future__ import annotations

import os
import tempfile
from unittest.mock import AsyncMock, patch
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.threat_intel.abusech import AbuseChProvider
from blackwall.threat_intel.abuseipdb import AbuseIPDBProvider
from blackwall.threat_intel.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerProvider,
)
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)
from blackwall.threat_intel.orchestrator import ThreatIntelOrchestrator
from blackwall.threat_intel.otx import AlienVaultOTXProvider
from tests.step_defs.async_utils import run_async

scenarios("../features/threat_intel_orchestration.feature")


class ThreatIntelBDDState:
    """State holder for threat intel BDD scenarios."""

    def __init__(self) -> None:
        self.repo: SQLiteThreatRepository | None = None
        self.db_path: str | None = None
        self.orchestrator: ThreatIntelOrchestrator | None = None
        self.otx_provider: AlienVaultOTXProvider | None = None
        self.abuseipdb_provider: AbuseIPDBProvider | None = None
        self.abusech_provider: AbuseChProvider | None = None
        self.circuit_breaker: CircuitBreaker | None = None
        self.circuit_breaker_provider: CircuitBreakerProvider | None = None
        self.last_response: ThreatIntelResponse | None = None
        self.last_error: Exception | None = None
        self.raw_call_count: int = 0


@pytest.fixture
def bdd_state() -> ThreatIntelBDDState:
    state = ThreatIntelBDDState()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        state.db_path = f.name
    state.repo = SQLiteThreatRepository(db_path=state.db_path)
    run_async(state.repo.initialize())
    yield state
    if state.repo:
        run_async(state.repo.close())
    if state.db_path and os.path.exists(state.db_path):
        os.remove(state.db_path)


# Scenario 1: Multi-provider cascade


@given("a Threat Intelligence Orchestrator configured with OTX, AbuseIPDB, and abuse.ch providers")
def given_orchestrator(bdd_state: ThreatIntelBDDState) -> None:
    bdd_state.otx_provider = AlienVaultOTXProvider(api_key="test-otx-key")
    bdd_state.abuseipdb_provider = AbuseIPDBProvider(api_key="test-abuseipdb-key")
    bdd_state.abusech_provider = AbuseChProvider(auth_key="test-abusech-key")

    bdd_state.orchestrator = ThreatIntelOrchestrator(
        repository=bdd_state.repo,
        primary_provider=bdd_state.otx_provider,
        secondary_providers=[
            bdd_state.abuseipdb_provider,
            bdd_state.abusech_provider,
        ],
        cache_enabled=True,
    )


@when(
    parsers.parse(
        'the orchestrator queries an IP indicator "{indicator}" with multiple feed responses'
    )
)
def when_query_ip_indicator(bdd_state: ThreatIntelBDDState, indicator: str) -> None:
    assert bdd_state.orchestrator is not None

    otx_resp = {
        "indicator": indicator,
        "type": "IPv4",
        "pulse_info": {"count": 1, "pulses": [{"name": "P1", "tags": ["c2"], "malware_families": []}]},
    }
    abuseipdb_resp = {
        "data": {
            "ipAddress": indicator,
            "abuseConfidenceScore": 75,
            "totalReports": 20,
            "numDistinctUsers": 8,
        }
    }
    abusech_resp = {
        "query_status": "ok",
        "data": [
            {
                "ioc": f"{indicator}:443",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 90,
                "tags": ["CobaltStrike"],
            }
        ],
    }

    with patch.object(
        bdd_state.otx_provider, "_execute_http_get", new_callable=AsyncMock
    ) as mock_otx, patch.object(
        bdd_state.abuseipdb_provider, "_execute_http_get", new_callable=AsyncMock
    ) as mock_abuseipdb, patch.object(
        bdd_state.abusech_provider, "_execute_post", new_callable=AsyncMock
    ) as mock_abusech:
        mock_otx.return_value = otx_resp
        mock_abuseipdb.return_value = abuseipdb_resp
        mock_abusech.return_value = abusech_resp

        bdd_state.last_response = run_async(
            bdd_state.orchestrator.lookup(indicator, ThreatIndicatorType.IPV4)
        )


@then("the aggregated risk score must match the highest confidence provider rating")
def then_check_highest_risk(bdd_state: ThreatIntelBDDState) -> None:
    assert bdd_state.last_response is not None
    # 90% confidence from ThreatFox -> 0.90 risk score
    assert bdd_state.last_response.risk_score >= 0.90


@then("the aggregated verdict must be flagged as malicious")
def then_check_is_malicious(bdd_state: ThreatIntelBDDState) -> None:
    assert bdd_state.last_response is not None
    assert bdd_state.last_response.is_malicious is True


@then(parsers.parse('the malware family "{family}" must be present in the response'))
def then_check_malware_family(bdd_state: ThreatIntelBDDState, family: str) -> None:
    assert bdd_state.last_response is not None
    assert family in bdd_state.last_response.malware_families


@then("the response must be cached for subsequent queries")
def then_check_cached(bdd_state: ThreatIntelBDDState) -> None:
    assert bdd_state.orchestrator is not None
    assert bdd_state.last_response is not None

    # Second lookup should return from cache
    second = run_async(
        bdd_state.orchestrator.lookup(
            bdd_state.last_response.indicator, ThreatIndicatorType.IPV4
        )
    )
    assert second.cached is True
    assert second.risk_score == bdd_state.last_response.risk_score


# Scenario 2: Circuit breaker resilience


class DummyFlakyProvider:
    name = "flaky_provider"
    supported_indicators = {ThreatIndicatorType.IPV4}

    def __init__(self, bdd_state: ThreatIntelBDDState) -> None:
        self.bdd_state = bdd_state

    async def lookup(
        self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float = 3.0
    ) -> ThreatIntelResponse:
        self.bdd_state.raw_call_count += 1
        raise ConnectionError("Remote server refused connection")

    async def is_healthy(self) -> bool:
        return False

    def get_remaining_budget(self) -> int:
        return 0


@given("a Threat Intelligence Provider protected by a 3-state Circuit Breaker")
def given_protected_provider(bdd_state: ThreatIntelBDDState) -> None:
    bdd_state.circuit_breaker = CircuitBreaker(
        name="flaky_test",
        failure_threshold=5,
        recovery_threshold=3,
        recovery_timeout=60.0,
        timeout=0.1,
    )
    dummy = DummyFlakyProvider(bdd_state)
    bdd_state.circuit_breaker_provider = CircuitBreakerProvider(
        dummy, circuit_breaker=bdd_state.circuit_breaker
    )


@when("the provider encounters 5 consecutive connection failures")
def when_five_failures(bdd_state: ThreatIntelBDDState) -> None:
    assert bdd_state.circuit_breaker_provider is not None
    for _ in range(5):
        run_async(
            bdd_state.circuit_breaker_provider.lookup("1.1.1.1", ThreatIndicatorType.IPV4)
        )


@then(parsers.parse('the circuit breaker state must become "{expected_state}"'))
def then_check_circuit_state(bdd_state: ThreatIntelBDDState, expected_state: str) -> None:
    assert bdd_state.circuit_breaker is not None
    assert bdd_state.circuit_breaker.state.value == expected_state


@then("subsequent queries must immediately return fallback heuristics without calling the provider")
def then_check_bypasses_provider(bdd_state: ThreatIntelBDDState) -> None:
    assert bdd_state.circuit_breaker_provider is not None
    calls_before = bdd_state.raw_call_count

    fallback = run_async(
        bdd_state.circuit_breaker_provider.lookup("1.1.1.2", ThreatIndicatorType.IPV4)
    )
    assert fallback.is_malicious is False
    assert fallback.risk_score == 0.0
    assert fallback.error is not None
    assert "open" in fallback.error.lower()
    # Inner provider was not called again!
    assert bdd_state.raw_call_count == calls_before


# Scenario 3: AbuseIPDB scoping & mapping


@given("an AbuseIPDB threat intelligence provider")
def given_abuseipdb(bdd_state: ThreatIntelBDDState) -> None:
    bdd_state.abuseipdb_provider = AbuseIPDBProvider(api_key="test-abuseipdb-key")


@when(
    parsers.parse(
        'an IP indicator "{indicator}" has an abuse confidence score of {score:d}'
    )
)
def when_abuseipdb_score(
    bdd_state: ThreatIntelBDDState, indicator: str, score: int
) -> None:
    assert bdd_state.abuseipdb_provider is not None

    mock_resp = {
        "data": {
            "ipAddress": indicator,
            "abuseConfidenceScore": score,
            "totalReports": 12,
            "numDistinctUsers": 5,
        }
    }
    with patch.object(
        bdd_state.abuseipdb_provider, "_execute_http_get", new_callable=AsyncMock
    ) as mock_get:
        mock_get.return_value = mock_resp
        bdd_state.last_response = run_async(
            bdd_state.abuseipdb_provider.lookup(indicator, ThreatIndicatorType.IPV4)
        )


@then(parsers.parse("the calculated risk score must be {expected_risk:f}"))
def then_calculated_risk(
    bdd_state: ThreatIntelBDDState, expected_risk: float
) -> None:
    assert bdd_state.last_response is not None
    assert bdd_state.last_response.risk_score == expected_risk


@then("the indicator must be flagged as malicious")
def then_indicator_is_malicious(bdd_state: ThreatIntelBDDState) -> None:
    assert bdd_state.last_response is not None
    assert bdd_state.last_response.is_malicious is True



@then(
    parsers.parse(
        'querying a domain indicator "{domain}" must raise ValueError without network requests'
    )
)
def then_domain_raises_value_error(
    bdd_state: ThreatIntelBDDState, domain: str
) -> None:
    assert bdd_state.abuseipdb_provider is not None
    with patch.object(
        bdd_state.abuseipdb_provider, "_execute_http_get", new_callable=AsyncMock
    ) as mock_get:
        with pytest.raises(ValueError, match="only supports IP indicators"):
            run_async(
                bdd_state.abuseipdb_provider.lookup(domain, ThreatIndicatorType.DOMAIN)
            )
        mock_get.assert_not_called()

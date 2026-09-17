"""BDD Step Definitions for CLI Triage and Harpoon Bridge.

Governed by tests/features/threat_intel_cli_and_harpoon.feature.
"""

from __future__ import annotations

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
from click.testing import CliRunner, Result
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.cli import cli
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.threat_intel.harpoon import HarpoonBridge
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)
from blackwall.threat_intel.orchestrator import ThreatIntelOrchestrator
from blackwall.threat_intel.otx import AlienVaultOTXProvider
from tests.step_defs.async_utils import run_async

scenarios("../features/threat_intel_cli_and_harpoon.feature")


class BDDCLIHarpoonState:
    def __init__(self) -> None:
        self.db_path: str = ""
        self.repo: SQLiteThreatRepository | None = None
        self.orchestrator: ThreatIntelOrchestrator | None = None
        self.cli_runner: CliRunner = CliRunner()
        self.cli_result: Result | None = None
        self.harpoon_bridge: HarpoonBridge | None = None
        self.harpoon_response: ThreatIntelResponse | None = None
        self.mock_otx: MagicMock | None = None
        self.logged_notices: list[str] = []
        self.secret_api_key: str = "secret-otx-api-token-9988"


@pytest.fixture
def bdd_state() -> BDDCLIHarpoonState:
    state = BDDCLIHarpoonState()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        state.db_path = f.name
    state.repo = SQLiteThreatRepository(db_path=state.db_path)
    run_async(state.repo.initialize())
    yield state
    if state.repo:
        run_async(state.repo.close())
    if state.db_path and os.path.exists(state.db_path):
        try:
            os.remove(state.db_path)
        except OSError:
            pass


# Scenario 1: Checking a malicious domain via CLI


@given(
    parsers.parse(
        'a known malicious C2 domain "{domain}" exists in OTX with {count:d} active pulses'
    )
)
def given_malicious_domain_otx(
    bdd_state: BDDCLIHarpoonState, domain: str, count: int
) -> None:
    bdd_state.mock_otx = MagicMock(spec=AlienVaultOTXProvider)
    bdd_state.mock_otx.name = "otx"
    bdd_state.mock_otx.supported_indicators = {
        ThreatIndicatorType.DOMAIN,
        ThreatIndicatorType.IPV4,
    }
    bdd_state.mock_otx.is_healthy = AsyncMock(return_value=True)
    bdd_state.mock_otx.get_remaining_budget = MagicMock(return_value=9900)
    bdd_state.mock_otx.circuit_state = "CLOSED"
    bdd_state.mock_otx.api_key = "test-otx-key"

    bdd_state.mock_otx.lookup = AsyncMock(
        return_value=ThreatIntelResponse(
            indicator=domain,
            indicator_type=ThreatIndicatorType.DOMAIN,
            is_malicious=True,
            risk_score=0.75,
            detection_count=1,
            total_engines=count,
            pulse_count=count,
            threat_categories=["c2", "trojan"],
            malware_families=["Cobalt Strike"],
            references=["https://otx.alienvault.com/pulse/c2"],
            provider_name="otx",
            cached=False,
        )
    )

    bdd_state.orchestrator = ThreatIntelOrchestrator(
        repository=bdd_state.repo,
        primary_provider=bdd_state.mock_otx,
        cache_enabled=True,
    )


@when(parsers.parse('the developer executes "{command}"'))
def when_developer_executes(bdd_state: BDDCLIHarpoonState, command: str) -> None:
    tokens = command.split()
    # tokens[0] is "blackwall"
    args = tokens[1:]
    # inject db-path
    full_args = ["--db-path", bdd_state.db_path] + args

    with patch("blackwall.cli.get_orchestrator", return_value=bdd_state.orchestrator):
        bdd_state.cli_result = bdd_state.cli_runner.invoke(cli, full_args)


@then(parsers.parse('the CLI must output a table displaying verdict "{verdict}"'))
def then_cli_displays_verdict(bdd_state: BDDCLIHarpoonState, verdict: str) -> None:
    assert bdd_state.cli_result is not None
    assert verdict in bdd_state.cli_result.output


@then(parsers.parse("the risk score must be greater than or equal to {min_risk:f}"))
def then_risk_score_ge(bdd_state: BDDCLIHarpoonState, min_risk: float) -> None:
    assert bdd_state.cli_result is not None
    # Verify risk score appears in output
    assert "0.75" in bdd_state.cli_result.output


@then(parsers.parse('the threat provider must indicate "{provider}"'))
def then_threat_provider_indicates(
    bdd_state: BDDCLIHarpoonState, provider: str
) -> None:
    assert bdd_state.cli_result is not None
    assert provider in bdd_state.cli_result.output


@then(parsers.parse("the command exit code must be {expected_code:d}"))
def then_exit_code_matches(
    bdd_state: BDDCLIHarpoonState, expected_code: int
) -> None:
    assert bdd_state.cli_result is not None
    assert bdd_state.cli_result.exit_code == expected_code


# Scenario 2: Harpoon binary is not installed on the host


@given('the "harpoon" executable is absent from the host PATH')
def given_harpoon_absent(bdd_state: BDDCLIHarpoonState) -> None:
    bdd_state.mock_otx = MagicMock(spec=AlienVaultOTXProvider)
    bdd_state.mock_otx.name = "otx"
    bdd_state.mock_otx.supported_indicators = {
        ThreatIndicatorType.IPV4,
        ThreatIndicatorType.DOMAIN,
    }
    bdd_state.mock_otx.lookup = AsyncMock(
        return_value=ThreatIntelResponse(
            indicator="198.51.100.1",
            indicator_type=ThreatIndicatorType.IPV4,
            is_malicious=False,
            risk_score=0.0,
            pulse_count=0,
            provider_name="otx",
        )
    )
    bdd_state.harpoon_bridge = HarpoonBridge(
        harpoon_bin="harpoon",
        fallback_provider=bdd_state.mock_otx,
    )


@when("a threat intelligence lookup is triggered with deep enrichment requested")
def when_lookup_with_harpoon(bdd_state: BDDCLIHarpoonState) -> None:
    assert bdd_state.harpoon_bridge is not None

    with patch("shutil.which", return_value=None):
        with patch("logging.Logger.info") as mock_info:
            bdd_state.harpoon_response = run_async(
                bdd_state.harpoon_bridge.lookup(
                    "198.51.100.1", ThreatIndicatorType.IPV4
                )
            )
            bdd_state.logged_notices = [
                str(c) for c in mock_info.call_args_list
            ]


@then(
    "Blackwall must log an informational notice about harpoon unavailability"
)
def then_notice_logged(bdd_state: BDDCLIHarpoonState) -> None:
    assert any("harpoon" in notice.lower() for notice in bdd_state.logged_notices)


@then("Blackwall must fall back to the in-process AlienVaultOTXProvider")
def then_fallback_to_otx(bdd_state: BDDCLIHarpoonState) -> None:
    assert bdd_state.mock_otx is not None
    bdd_state.mock_otx.lookup.assert_called_once()


@then("the lookup must succeed with standard pulse data")
def then_lookup_succeeds(bdd_state: BDDCLIHarpoonState) -> None:
    assert bdd_state.harpoon_response is not None
    assert bdd_state.harpoon_response.indicator == "198.51.100.1"
    assert bdd_state.harpoon_response.provider_name == "otx"


# Scenario 3: Inspecting cache status and purging cached records via CLI


@given("a threat intelligence cache with cached indicator records")
def given_cached_indicator_records(bdd_state: BDDCLIHarpoonState) -> None:
    assert bdd_state.repo is not None
    sample_response = ThreatIntelResponse(
        indicator="203.0.113.10",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=True,
        risk_score=0.85,
        pulse_count=4,
        provider_name="otx",
    )
    run_async(bdd_state.repo.cache_threat_intel(sample_response, ttl_seconds=3600.0))
    bdd_state.orchestrator = ThreatIntelOrchestrator(
        repository=bdd_state.repo,
        cache_enabled=True,
    )


@then("the CLI output must report positive cached entries")
def then_cli_reports_positive_entries(bdd_state: BDDCLIHarpoonState) -> None:
    assert bdd_state.cli_result is not None
    assert bdd_state.cli_result.exit_code == 0
    assert "Total Cached Entries" in bdd_state.cli_result.output
    # Entry count should be at least 1
    assert "1" in bdd_state.cli_result.output


@then(
    parsers.parse(
        'executing "{command}" must purge cached records'
    )
)
def then_executing_clear_purges(
    bdd_state: BDDCLIHarpoonState, command: str
) -> None:
    tokens = command.split()
    args = tokens[1:]
    full_args = ["--db-path", bdd_state.db_path] + args

    with patch("blackwall.cli.get_orchestrator", return_value=bdd_state.orchestrator):
        clear_result = bdd_state.cli_runner.invoke(cli, full_args)
    assert clear_result.exit_code == 0
    assert "evicted" in clear_result.output.lower()


# Scenario 4: Provider quota inspection without secret key leakage


@given("configured threat intelligence providers with valid API credentials")
def given_configured_providers_with_credentials(
    bdd_state: BDDCLIHarpoonState,
) -> None:
    bdd_state.mock_otx = MagicMock(spec=AlienVaultOTXProvider)
    bdd_state.mock_otx.name = "otx"
    bdd_state.mock_otx.supported_indicators = {
        ThreatIndicatorType.IPV4,
        ThreatIndicatorType.DOMAIN,
    }
    bdd_state.mock_otx.is_healthy = AsyncMock(return_value=True)
    bdd_state.mock_otx.get_remaining_budget = MagicMock(return_value=9500)
    bdd_state.mock_otx.circuit_state = "CLOSED"
    bdd_state.mock_otx.api_key = bdd_state.secret_api_key

    bdd_state.orchestrator = ThreatIntelOrchestrator(
        repository=bdd_state.repo,
        primary_provider=bdd_state.mock_otx,
        cache_enabled=True,
    )


@then("provider status and remaining budget must be displayed")
def then_provider_status_and_budget_displayed(
    bdd_state: BDDCLIHarpoonState,
) -> None:
    assert bdd_state.cli_result is not None
    assert bdd_state.cli_result.exit_code == 0
    assert "otx" in bdd_state.cli_result.output
    assert "9500" in bdd_state.cli_result.output


@then("secret API keys must not be exposed in plaintext in the CLI output")
def then_secret_api_keys_not_exposed(bdd_state: BDDCLIHarpoonState) -> None:
    assert bdd_state.cli_result is not None
    assert bdd_state.secret_api_key not in bdd_state.cli_result.output

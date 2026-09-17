"""BDD Step Definitions for Native CLI Threat Intelligence Triage (`tests/features/threat_intel_cli.feature`)."""

from __future__ import annotations

import json
import os
import tempfile
from click.testing import CliRunner, Result
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.cli import cli
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)
from tests.step_defs.async_utils import run_async

scenarios("../features/threat_intel_cli.feature")


class BDDCLIState:
    """State container for CLI triage BDD scenarios."""

    def __init__(self) -> None:
        self.db_path: str = ""
        self.repo: SQLiteThreatRepository | None = None
        self.runner: CliRunner = CliRunner()
        self.result: Result | None = None
        self.json_data: dict | None = None


@pytest.fixture
def bdd_state() -> BDDCLIState:
    state = BDDCLIState()
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


@given(
    parsers.parse(
        'a known malicious domain indicator "{domain}" with risk score {risk_score:f}'
    )
)
def given_malicious_domain(
    bdd_state: BDDCLIState, domain: str, risk_score: float
) -> None:
    resp = ThreatIntelResponse(
        indicator=domain,
        indicator_type=ThreatIndicatorType.DOMAIN,
        is_malicious=True,
        risk_score=risk_score,
        pulse_count=4,
        threat_categories=["c2", "malware"],
        malware_families=["Cobalt Strike"],
        provider_name="otx",
    )
    assert bdd_state.repo is not None
    run_async(bdd_state.repo.cache_threat_intel(resp, provider="aggregate"))
    run_async(bdd_state.repo.cache_threat_intel(resp, provider="otx"))


@given(
    parsers.parse(
        'a known suspicious IPv4 indicator "{ip}" with risk score {risk_score:f}'
    )
)
def given_suspicious_ip(
    bdd_state: BDDCLIState, ip: str, risk_score: float
) -> None:
    resp = ThreatIntelResponse(
        indicator=ip,
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=False,
        risk_score=risk_score,
        pulse_count=1,
        threat_categories=["scanner"],
        provider_name="otx",
    )
    assert bdd_state.repo is not None
    run_async(bdd_state.repo.cache_threat_intel(resp, provider="aggregate"))
    run_async(bdd_state.repo.cache_threat_intel(resp, provider="otx"))


@given(
    parsers.parse(
        'a known benign file hash indicator "{file_hash}" with risk score {risk_score:f}'
    )
)
def given_benign_file_hash(
    bdd_state: BDDCLIState, file_hash: str, risk_score: float
) -> None:
    resp = ThreatIntelResponse(
        indicator=file_hash,
        indicator_type=ThreatIndicatorType.FILE_HASH,
        is_malicious=False,
        risk_score=risk_score,
        pulse_count=0,
        threat_categories=[],
        provider_name="otx",
    )
    assert bdd_state.repo is not None
    run_async(bdd_state.repo.cache_threat_intel(resp, provider="aggregate"))
    run_async(bdd_state.repo.cache_threat_intel(resp, provider="otx"))


@when(parsers.parse('the user runs "blackwall check {args}"'))
def when_user_runs_check(bdd_state: BDDCLIState, args: str) -> None:
    cmd_args = ["--db-path", bdd_state.db_path, "check"] + args.split()
    bdd_state.result = bdd_state.runner.invoke(cli, cmd_args)
    if "--format json" in args and bdd_state.result.exit_code == 0:
        bdd_state.json_data = json.loads(bdd_state.result.output)


@then("the command exit code must be 0")
def then_exit_code_zero(bdd_state: BDDCLIState) -> None:
    assert bdd_state.result is not None
    assert (
        bdd_state.result.exit_code == 0
    ), f"Command failed with output: {bdd_state.result.output}"


@then(parsers.parse('the output table must display verdict "{verdict}"'))
def then_output_table_verdict(bdd_state: BDDCLIState, verdict: str) -> None:
    assert bdd_state.result is not None
    assert verdict in bdd_state.result.output


@then(parsers.parse('the output table must display risk score "{score_str}"'))
def then_output_table_risk_score(bdd_state: BDDCLIState, score_str: str) -> None:
    assert bdd_state.result is not None
    assert score_str in bdd_state.result.output


@then(parsers.parse('the output table must display provider "{provider}"'))
def then_output_table_provider(bdd_state: BDDCLIState, provider: str) -> None:
    assert bdd_state.result is not None
    assert provider in bdd_state.result.output


@then("the output must be valid JSON")
def then_output_valid_json(bdd_state: BDDCLIState) -> None:
    assert bdd_state.json_data is not None


@then(parsers.parse('the JSON response must have verdict "{verdict}"'))
def then_json_verdict(bdd_state: BDDCLIState, verdict: str) -> None:
    assert bdd_state.json_data is not None
    assert bdd_state.json_data.get("verdict") == verdict


@then(parsers.parse("the JSON response must have risk_score {expected_score:f}"))
def then_json_risk_score(bdd_state: BDDCLIState, expected_score: float) -> None:
    assert bdd_state.json_data is not None
    assert abs(bdd_state.json_data.get("risk_score", -1) - expected_score) < 0.01


@then(parsers.parse('the JSON response must have indicator_type "{ind_type}"'))
def then_json_indicator_type(bdd_state: BDDCLIState, ind_type: str) -> None:
    assert bdd_state.json_data is not None
    assert bdd_state.json_data.get("indicator_type") == ind_type

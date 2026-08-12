"""Pytest-BDD step definitions for attacker attribution model validation."""

from datetime import datetime, timezone
import json
import os
from unittest.mock import patch
from uuid import uuid4
import pytest
from pydantic import ValidationError
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.models import (
    AttackerIdentity,
    AttackerProfile,
    IdentitySource,
    IncidentReport,
    ToolCallContext,
    VerdictDecision,
)
from blackwall.attribution.extractor import AttackerIdentityExtractor
from blackwall.attribution.reporter import IncidentReportGenerator

scenarios("../features/attacker_attribution.feature")


class AttributionScenarioState:
    """Container for state during scenario execution."""

    def __init__(self):
        self.identity1: AttackerIdentity | None = None
        self.identity2: AttackerIdentity | None = None
        self.profile: AttackerProfile | None = None
        self.report: IncidentReport | None = None
        self.json_output: str = ""
        self.markdown_output: str = ""
        self.error: Exception | None = None
        self.agent_id1: str = ""
        self.agent_id2: str = ""
        self.thread_id: str = ""
        self.score: float = 0.5
        self.timestamp: datetime | None = None
        # Track 2A state
        self.extractor: AttackerIdentityExtractor | None = None
        self.extractor_metadata: dict | None = None
        self.extractor_tool_context: ToolCallContext | None = None
        self.extracted_identity: AttackerIdentity | None = None
        self.extractor_force_fail: bool = False
        # Track 2B state
        self.generator: IncidentReportGenerator | None = None
        self.generator_tool_context: ToolCallContext | None = None
        self.generator_identity: AttackerIdentity | None = None
        self.generator_profile: AttackerProfile | None = None
        self.built_report: IncidentReport | None = None
        # Track 3 profile DB state
        self.profile_db_repo: Any = None
        self.profile_db_fingerprint: str = ""
        self.profile_db_updated_profile: AttackerProfile | None = None
        # Track 4 e2e state
        self.e2e_context: ToolCallContext | None = None
        self.e2e_verdict: Verdict | None = None
        self.e2e_repo: Any = None
        self.e2e_agent_name: str = ""
        self.e2e_stderr: str = ""


@pytest.fixture
def state():
    return AttributionScenarioState()


# Scenario: Generate deterministic SHA-256 fingerprint
@given(
    parsers.parse(
        'two identical attacker identity attributes with agent_id "{agent_id}" and thread_id "{thread_id}"'
    )
)
def set_identical_identity_attributes(
    state: AttributionScenarioState, agent_id: str, thread_id: str
):
    state.agent_id1 = agent_id
    state.agent_id2 = agent_id
    state.thread_id = thread_id


@when("the AttackerIdentity objects are instantiated")
def instantiate_identities(state: AttributionScenarioState):
    state.identity1 = AttackerIdentity(
        agent_id=state.agent_id1,
        thread_id=state.thread_id,
        primary_source=IdentitySource.ADK_METADATA,
    )
    state.identity2 = AttackerIdentity(
        agent_id=state.agent_id2,
        thread_id=state.thread_id,
        primary_source=IdentitySource.ADK_METADATA,
    )


@then("both identity objects MUST produce the exact same 64-character SHA-256 identity_fingerprint")
def verify_identical_fingerprints(state: AttributionScenarioState):
    assert len(state.identity1.identity_fingerprint) == 64
    assert len(state.identity2.identity_fingerprint) == 64
    assert state.identity1.identity_fingerprint == state.identity2.identity_fingerprint


# Scenario: Generate distinct fingerprints
@given(
    parsers.parse(
        'two attacker identities with different agent_ids "{id1}" and "{id2}"'
    )
)
def set_distinct_identity_attributes(
    state: AttributionScenarioState, id1: str, id2: str
):
    state.agent_id1 = id1
    state.agent_id2 = id2
    state.thread_id = "th-same"


@then("their identity_fingerprint strings MUST be distinct")
def verify_distinct_fingerprints(state: AttributionScenarioState):
    assert state.identity1.identity_fingerprint != state.identity2.identity_fingerprint


# Scenario: Valid score and UTC timestamp
@given(parsers.parse("a valid UTC timestamp and threat_score {score:f}"))
def set_valid_utc_and_score(state: AttributionScenarioState, score: float):
    state.timestamp = datetime.now(timezone.utc)
    state.score = score


@when("the AttackerProfile object is instantiated")
def instantiate_attacker_profile(state: AttributionScenarioState):
    try:
        state.profile = AttackerProfile(
            fingerprint="a" * 64,
            first_seen=state.timestamp or datetime.now(timezone.utc),
            last_seen=state.timestamp or datetime.now(timezone.utc),
            threat_score=state.score,
        )
    except Exception as exc:
        state.error = exc


@then(parsers.parse("the profile MUST store the threat_score {expected_score:f} and UTC timestamp without error"))
def verify_profile_valid(state: AttributionScenarioState, expected_score: float):
    assert state.error is None
    assert state.profile is not None
    assert state.profile.threat_score == pytest.approx(expected_score)


# Scenario: Invalid threat score out of bounds
@given(parsers.parse("an invalid threat_score {score:f}"))
def set_invalid_score(state: AttributionScenarioState, score: float):
    state.score = score
    state.timestamp = datetime.now(timezone.utc)


@then("a ValidationError MUST be raised for threat_score out of bounds")
def verify_score_validation_error(state: AttributionScenarioState):
    assert isinstance(state.error, ValidationError)


# Scenario: Naive timestamp
@given("a naive timestamp without timezone info for AttackerProfile")
def set_naive_timestamp(state: AttributionScenarioState):
    state.timestamp = datetime.now()  # naive
    state.score = 0.5


@then("a ValidationError MUST be raised for non-UTC timestamp")
def verify_timestamp_validation_error(state: AttributionScenarioState):
    assert isinstance(state.error, ValidationError)


# Scenario: Serialization to Markdown and JSON
@given(parsers.parse('a valid IncidentReport with BLOCK verdict for agent "{agent_name}"'))
def set_valid_incident_report_scenario(
    state: AttributionScenarioState, agent_name: str
):
    now = datetime.now(timezone.utc)
    identity = AttackerIdentity(
        agent_name=agent_name,
        thread_id="th-999",
        primary_source=IdentitySource.ADK_METADATA,
    )
    profile = AttackerProfile(
        fingerprint=identity.identity_fingerprint,
        first_seen=now,
        last_seen=now,
        threat_score=0.95,
    )
    state.report = IncidentReport(
        event_id=uuid4(),
        verdict=VerdictDecision.BLOCK,
        attacker_identity=identity,
        attacker_profile=profile,
        exploited_tool="execute_bash",
        sanitized_arguments={"cmd": "whoami"},
        attack_technique="Unsafe Command Execution",
        mitigation_action="Operation blocked",
        recommended_user_action="Inspect agent logs",
        attribution_confidence=0.99,
    )


@when("the report serialization helpers to_json and to_markdown are executed")
def execute_report_serialization(state: AttributionScenarioState):
    assert state.report is not None
    state.json_output = state.report.to_json()
    state.markdown_output = state.report.to_markdown()


@then(parsers.parse('to_json MUST return a valid JSON string containing "{expected_agent}"'))
def verify_json_output(state: AttributionScenarioState, expected_agent: str):
    parsed = json.loads(state.json_output)
    assert parsed["attacker_identity"]["agent_name"] == expected_agent


@then(
    parsers.parse(
        'to_markdown MUST return a formatted Markdown string containing "{expected_header}"'
    )
)
def verify_markdown_output(state: AttributionScenarioState, expected_header: str):
    assert expected_header in state.markdown_output


# ===========================================================================
# Track 2A: Identity Extractor BDD Step Definitions
# ===========================================================================

@given(
    parsers.parse(
        'an ADK tool call metadata containing agent_id "{agent_id}" and agent_name "{agent_name}" and thread_id "{thread_id}"'
    )
)
def set_full_adk_metadata(
    state: AttributionScenarioState,
    agent_id: str,
    agent_name: str,
    thread_id: str,
):
    state.extractor = AttackerIdentityExtractor()
    state.extractor_metadata = {
        "agent_id": agent_id,
        "agent_name": agent_name,
        "thread_id": thread_id,
    }
    state.extractor_tool_context = ToolCallContext(
        tool_name="execute_bash",
        arguments={"cmd": "ls"},
        metadata=state.extractor_metadata,
    )


@given("an empty ADK metadata dictionary")
def set_empty_metadata(state: AttributionScenarioState):
    state.extractor = AttackerIdentityExtractor()
    state.extractor_metadata = {}
    state.extractor_tool_context = ToolCallContext(
        tool_name="read_file",
        arguments={"path": "/etc/passwd"},
        metadata=None,
    )


@given("a tool call context where extraction will fail due to injected errors")
def set_failing_extraction_context(state: AttributionScenarioState):
    state.extractor = AttackerIdentityExtractor()
    state.extractor_metadata = {"agent_id": "trigger-fail"}
    state.extractor_tool_context = ToolCallContext(
        tool_name="execute_bash",
        arguments={},
        metadata=state.extractor_metadata,
    )
    state.extractor_force_fail = True


@when("the AttackerIdentityExtractor processes the metadata")
def run_extractor(state: AttributionScenarioState):
    assert state.extractor is not None
    state.extracted_identity = state.extractor.extract(
        context=state.extractor_tool_context,
        metadata=state.extractor_metadata,
    )


@when("the AttackerIdentityExtractor processes the metadata with forced failures")
def run_extractor_with_forced_failure(state: AttributionScenarioState):
    assert state.extractor is not None
    with patch.object(
        state.extractor, "_extract_from_adk", side_effect=RuntimeError("Forced ADK failure")
    ):
        with patch.object(
            state.extractor, "_extract_from_process", side_effect=OSError("Forced OS failure")
        ):
            state.extracted_identity = state.extractor.extract(
                context=state.extractor_tool_context,
                metadata=state.extractor_metadata,
            )


@then(parsers.parse('the extracted AttackerIdentity MUST have agent_id "{expected_agent_id}"'))
def verify_extracted_agent_id(state: AttributionScenarioState, expected_agent_id: str):
    assert state.extracted_identity is not None
    assert state.extracted_identity.agent_id == expected_agent_id


@then(parsers.parse('the extracted identity MUST have primary_source "{expected_source}"'))
def verify_extracted_primary_source(state: AttributionScenarioState, expected_source: str):
    assert state.extracted_identity is not None
    assert state.extracted_identity.primary_source.value == expected_source


@then("the extracted identity MUST have a 64-character SHA-256 identity_fingerprint")
def verify_extracted_fingerprint_length(state: AttributionScenarioState):
    assert state.extracted_identity is not None
    assert len(state.extracted_identity.identity_fingerprint) == 64
    assert all(c in "0123456789abcdef" for c in state.extracted_identity.identity_fingerprint)


@then("the extracted identity MUST contain the current process PID")
def verify_extracted_pid(state: AttributionScenarioState):
    assert state.extracted_identity is not None
    assert state.extracted_identity.process_pid == os.getpid()


@then(parsers.parse('the result MUST be a valid AttackerIdentity with agent_id "{expected_agent_id}"'))
def verify_unresolved_attacker_identity(state: AttributionScenarioState, expected_agent_id: str):
    assert state.extracted_identity is not None
    assert isinstance(state.extracted_identity, AttackerIdentity)
    assert state.extracted_identity.agent_id == expected_agent_id or \
        state.extracted_identity.agent_name == expected_agent_id


@then("no exception MUST propagate from the extractor")
def verify_no_exception_propagated(state: AttributionScenarioState):
    # If we reach this step, no exception was raised — assertion is implicit
    assert state.extracted_identity is not None


# ===========================================================================
# Track 2B: Incident Report Generator BDD Step Definitions
# ===========================================================================

@given(
    parsers.parse(
        'a tool call context with a sensitive OPENAI_API_KEY argument "{api_key_value}"'
    )
)
def set_sensitive_tool_context(state: AttributionScenarioState, api_key_value: str):
    state.generator = IncidentReportGenerator()
    state.generator_tool_context = ToolCallContext(
        tool_name="execute_bash",
        arguments={"OPENAI_API_KEY": api_key_value, "cmd": "exfil"},
        metadata=None,
    )
    now = datetime.now(timezone.utc)
    identity = AttackerIdentity(
        agent_id="agent-redact-test",
        agent_name="RedactionTestAgent",
        thread_id="th-redact",
        primary_source=IdentitySource.ADK_METADATA,
    )
    state.generator_identity = identity
    state.generator_profile = AttackerProfile(
        fingerprint=identity.identity_fingerprint,
        first_seen=now,
        last_seen=now,
        threat_score=0.80,
    )


@given(
    parsers.parse(
        'a valid tool call context for agent "{agent_name}" with verdict BLOCK'
    )
)
def set_valid_reporter_context(state: AttributionScenarioState, agent_name: str):
    state.generator = IncidentReportGenerator()
    state.generator_tool_context = ToolCallContext(
        tool_name="execute_bash",
        arguments={"cmd": "whoami"},
        metadata=None,
    )
    now = datetime.now(timezone.utc)
    identity = AttackerIdentity(
        agent_name=agent_name,
        agent_id="agent-reporter-bdd",
        thread_id="th-bdd-reporter",
        primary_source=IdentitySource.ADK_METADATA,
    )
    state.generator_identity = identity
    state.generator_profile = AttackerProfile(
        fingerprint=identity.identity_fingerprint,
        first_seen=now,
        last_seen=now,
        threat_score=0.90,
    )


@when("the IncidentReportGenerator builds a BLOCK verdict report")
def run_report_generator(state: AttributionScenarioState):
    assert state.generator is not None
    assert state.generator_tool_context is not None
    state.built_report = state.generator.build(
        event_id=uuid4(),
        verdict=VerdictDecision.BLOCK,
        identity=state.generator_identity,
        profile=state.generator_profile,
        tool_context=state.generator_tool_context,
        technique="Unauthorized Operation",
        mitigation="Operation blocked by Blackwall",
        recommended_action="Revoke agent credentials",
        confidence=0.95,
    )


@then(parsers.parse('the report sanitized_arguments MUST NOT contain "{secret_value}"'))
def verify_secret_not_in_report(state: AttributionScenarioState, secret_value: str):
    assert state.built_report is not None
    assert secret_value not in str(state.built_report.sanitized_arguments)


@then("the report sanitized_arguments MUST contain a redaction placeholder")
def verify_placeholder_in_report(state: AttributionScenarioState):
    assert state.built_report is not None
    sanitized_str = str(state.built_report.sanitized_arguments)
    assert "[[" in sanitized_str or "[REDACTED]" in sanitized_str or "REDACTED" in sanitized_str


@then(parsers.parse('the report to_markdown output MUST contain "{expected_content}"'))
def verify_markdown_contains(state: AttributionScenarioState, expected_content: str):
    assert state.built_report is not None
    assert expected_content in state.built_report.to_markdown()


# ===========================================================================
# Track 3: Profile DB BDD Step Definitions
# ===========================================================================

@given(
    parsers.parse(
        'an existing AttackerProfile for fingerprint "{fingerprint}" with total_attacks {attacks:d}'
    )
)
def set_existing_profile_db(
    state: AttributionScenarioState, fingerprint: str, attacks: int
):
    import tempfile
    from blackwall.db.repository import SQLiteThreatRepository
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    state.profile_db_repo = SQLiteThreatRepository(db_path=tmp.name)
    state.profile_db_fingerprint = fingerprint

    now = datetime.now(timezone.utc)
    profile = AttackerProfile(
        fingerprint=fingerprint,
        first_seen=now,
        last_seen=now,
        total_attacks=attacks,
        threat_score=0.50,
        targeted_tools=["read_file"],
    )
    import asyncio
    asyncio.run(state.profile_db_repo.upsert_attacker_profile(profile))


@when(
    parsers.parse(
        'a new BLOCK verdict is assigned to fingerprint "{fingerprint}" with score {score:f} and targeted_tool "{tool_name}"'
    )
)
def update_profile_db_scenario(
    state: AttributionScenarioState, fingerprint: str, score: float, tool_name: str
):
    assert state.profile_db_repo is not None
    now = datetime.now(timezone.utc)
    profile = AttackerProfile(
        fingerprint=fingerprint,
        first_seen=now,
        last_seen=now,
        total_attacks=1,
        threat_score=score,
        targeted_tools=[tool_name],
    )
    import asyncio
    state.profile_db_updated_profile = asyncio.run(
        state.profile_db_repo.upsert_attacker_profile(profile)
    )


@then(
    parsers.parse(
        'the total_attacks count for fingerprint "{fingerprint}" MUST increment to {expected_attacks:d}'
    )
)
def verify_profile_attacks_incremented(
    state: AttributionScenarioState, fingerprint: str, expected_attacks: int
):
    assert state.profile_db_updated_profile is not None
    assert state.profile_db_updated_profile.total_attacks == expected_attacks


@then(
    parsers.parse(
        'the threat_score for fingerprint "{fingerprint}" MUST update to {expected_score:f}'
    )
)
def verify_profile_score_updated(
    state: AttributionScenarioState, fingerprint: str, expected_score: float
):
    assert state.profile_db_updated_profile is not None
    assert state.profile_db_updated_profile.threat_score == pytest.approx(expected_score)


@then(parsers.parse('the targeted_tools MUST contain "{tool_name}"'))
def verify_profile_targeted_tools(
    state: AttributionScenarioState, tool_name: str
):
    assert state.profile_db_updated_profile is not None
    assert tool_name in state.profile_db_updated_profile.targeted_tools


# ===========================================================================
# Track 4: End-to-End Interception BDD Step Definitions
# ===========================================================================

@given(
    parsers.parse(
        'a rogue ADK tool call context for tool "{tool_name}" with command "{cmd}" and agent_name "{agent_name}"'
    )
)
def set_e2e_rogue_context(
    state: AttributionScenarioState, tool_name: str, cmd: str, agent_name: str
):
    import tempfile
    from blackwall.db.repository import SQLiteThreatRepository
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    state.e2e_repo = SQLiteThreatRepository(db_path=tmp.name)
    import asyncio
    asyncio.run(state.e2e_repo.initialize())

    state.e2e_agent_name = agent_name
    state.e2e_context = ToolCallContext(
        tool_name=tool_name,
        arguments={"cmd": cmd},
        metadata={
            "agent_id": f"id-{agent_name}",
            "agent_name": agent_name,
            "thread_id": "th-e2e-100",
        },
    )


@when("the tool call context is evaluated by SyncResolver")
def evaluate_e2e_sync_resolver(state: AttributionScenarioState, capsys):
    from unittest.mock import MagicMock
    from blackwall.sync_resolver import SyncResolver
    assert state.e2e_context is not None
    assert state.e2e_repo is not None

    mock_client = MagicMock()
    resolver = SyncResolver(
        client=mock_client,
        repo=state.e2e_repo,
        demo_mode=True,
    )

    import asyncio
    state.e2e_verdict = asyncio.run(resolver.evaluate(state.e2e_context))
    captured = capsys.readouterr()
    state.e2e_stderr = captured.err


@then(parsers.parse('the evaluation verdict MUST be {expected_verdict}'))
def verify_e2e_verdict(state: AttributionScenarioState, expected_verdict: str):
    assert state.e2e_verdict is not None
    assert state.e2e_verdict.decision.value == expected_verdict


@then(
    parsers.parse(
        'an AttackerProfile for agent "{agent_name}" MUST be persisted in SQLite with total_attacks {expected_attacks:d}'
    )
)
def verify_e2e_persisted_profile(
    state: AttributionScenarioState, agent_name: str, expected_attacks: int
):
    assert state.e2e_context is not None
    assert state.e2e_repo is not None
    extractor = AttackerIdentityExtractor()
    identity = extractor.extract(state.e2e_context, state.e2e_context.metadata)
    fp = identity.identity_fingerprint

    import asyncio
    profile = asyncio.run(state.e2e_repo.get_attacker_profile(fp))
    assert profile is not None
    assert profile.total_attacks == expected_attacks


@then(parsers.parse('the CLI alert sink MUST output the incident report containing "{agent_name}"'))
def verify_e2e_cli_alert(state: AttributionScenarioState, agent_name: str):
    assert "# Blackwall Incident Attribution Report" in state.e2e_stderr
    assert agent_name in state.e2e_stderr


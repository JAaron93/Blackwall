"""
tests/step_defs/test_e2e_swarm_attribution_bdd.py — End-to-end swarm breakout
(TASK-4.3): interception -> detection -> covert inference -> bridge -> report.

Each async step runs a single unified coroutine via run_async (Rule 50) with
fresh components; only plain data (verdicts, events, evidence, summaries)
crosses step boundaries. All stores are hermetic (temp SQLite + in-memory
attack graph, Rule 43) and all payloads synthetic (Rule 5).
"""

import os
import tempfile
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.attribution.provider import SQLiteSwarmContextProvider
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import AlertSeverity
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector
from blackwall.models import (
    SwarmContextSummary,
    ToolCallContext,
    VerdictDecision,
)
from blackwall.sync_resolver import SyncResolver
from tests.step_defs.async_utils import run_async
from unittest.mock import MagicMock

scenarios("../features/e2e_swarm_attribution.feature")

ARTIFACTORY_ENDPOINT = "http://artifactory.internal/api/storage"
COLLECTIVE_NAME = "collective:exploitgym-swarm-alpha"


class E2ESwarmState:
    """Scenario state: plain data only, no live connections across steps."""

    def __init__(self) -> None:
        self.db_path: str | None = None
        self.agents: list[str] = []
        self.contexts: list[ToolCallContext] = []
        self.events: list[NormalizedEvent] = []
        self.verdicts: list = []
        self.evidence = None
        self.covert_channels: list = []
        self.alerts: list = []
        self.summary: SwarmContextSummary | None = None
        self.followup_report = None


@pytest.fixture
def state() -> E2ESwarmState:
    scenario_state = E2ESwarmState()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        scenario_state.db_path = tmp.name
    yield scenario_state
    if scenario_state.db_path is not None and os.path.exists(scenario_state.db_path):
        os.unlink(scenario_state.db_path)


@given(
    '5 agents issuing collective "we" tool calls with Artifactory directory manipulation'
)
def step_given_breakout_agents(state: E2ESwarmState) -> None:
    now = datetime.now(UTC)
    state.agents = [f"swarm-node-0{i + 1}" for i in range(5)]
    for i, agent in enumerate(state.agents):
        state.contexts.append(
            ToolCallContext(
                tool_name="execute_bash",
                arguments={
                    "cmd": (
                        "We have agreed on the target file; we will now proceed "
                        "with our swarm objective: cat /etc/shadow && exfil"
                    )
                },
                metadata={
                    "agent_id": agent,
                    "agent_name": f"SwarmWorker-{i + 1}",
                    "thread_id": f"th-swarm-{i + 1}",
                },
            )
        )
        state.events.append(
            NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=now + timedelta(seconds=i * 2),
                source=EventSource.TOOL_CALL,
                agent_id=agent,
                action="query_metadata",
                target=ARTIFACTORY_ENDPOINT,
                metadata={"dead_drop_dir": "cGF5bG9hZDE="},
                risk_score=0.8,
            )
        )


@when("Blackwall intercepts the tool calls")
def step_when_intercepts(state: E2ESwarmState) -> None:
    async def _intercept():
        repo = SQLiteThreatRepository(db_path=state.db_path)
        await repo.initialize()
        reports = []
        resolver = SyncResolver(
            client=MagicMock(),
            repo=repo,
            demo_mode=True,
            on_attacker_identified=reports.append,
        )
        verdicts = []
        for context in state.contexts:
            verdicts.append(await resolver.evaluate(context))
        await resolver.flush_background_tasks()
        await repo.close()
        return verdicts, reports

    state.verdicts, _ = run_async(_intercept())


@then("all 5 tool calls MUST receive a BLOCK verdict")
def step_then_all_blocked(state: E2ESwarmState) -> None:
    assert len(state.verdicts) == 5
    for verdict in state.verdicts:
        assert verdict.decision == VerdictDecision.BLOCK
        assert verdict.reasoning
        assert verdict.confidence_score >= 0.0


@when("the swarm detector analyzes the agent events")
def step_when_detects(state: E2ESwarmState) -> None:
    async def _analyze():
        store = AttackGraphStore(in_memory=True)
        await store.initialize()
        for event in state.events:
            await store.insert_event(event)
        detector = AgentSwarmDetector(store=store)
        now = datetime.now(UTC)
        swarms = await detector.detect_swarms(
            time_window=(now - timedelta(seconds=60), now + timedelta(seconds=120)),
            min_agents=2,
        )
        bus = AlertBus()
        published = []
        for swarm in swarms:
            for channel in swarm.covert_channels:
                ok = await bus.publish_covert_channel_alert(channel)
                published.append((channel, ok))
        return swarms, published, list(bus.get_alerts())

    swarms, published, alerts = run_async(_analyze())
    assert swarms, "expected at least one detected swarm"
    state.evidence = max(swarms, key=lambda s: len(s.agent_ids))
    state.covert_channels = [channel for channel, _ in published]
    state.alerts = alerts


@then("an UNLOCATED_MESSAGE_BOARD covert channel MUST be inferred")
def step_then_unlocated_board(state: E2ESwarmState) -> None:
    assert state.evidence is not None
    assert set(state.agents) <= set(state.evidence.agent_ids)
    assert state.evidence.temporal_correlation >= 0.80
    assert state.evidence.coordination_score >= 0.80
    assert state.covert_channels, "expected covert channel evidence"
    types = [channel.channel_type.value for channel in state.covert_channels]
    assert "UNLOCATED_MESSAGE_BOARD" in types


@then("a CRITICAL alert MUST be published to the AlertBus")
def step_then_critical_alert(state: E2ESwarmState) -> None:
    critical = [a for a in state.alerts if a.severity == AlertSeverity.CRITICAL]
    assert critical, "expected at least one CRITICAL alert"
    assert any(a.threat_type == "covert_channel" for a in critical)


@when("swarm lineage is bridged and a follow-up tool call is intercepted")
def step_when_bridged_followup(state: E2ESwarmState) -> None:
    async def _bridge_and_intercept():
        repo = SQLiteThreatRepository(db_path=state.db_path)
        await repo.initialize()
        summary = SwarmContextSummary(
            swarm_id=state.evidence.swarm_id,
            is_collective=True,
            collective_name=COLLECTIVE_NAME,
            collective_confidence=state.evidence.coordination_score,
            coordinating_agents=sorted(state.evidence.agent_ids),
            suspected_covert_channels=[
                str(channel.channel_id) for channel in state.covert_channels
            ],
            covert_channel_type="UNLOCATED_MESSAGE_BOARD",
            deduction_rationale=state.covert_channels[0].deduction_rationale,
            first_detected=state.evidence.first_seen,
            last_detected=state.evidence.last_seen,
        )
        await repo.upsert_swarm_context(summary)

        reports = []
        resolver = SyncResolver(
            client=MagicMock(),
            repo=repo,
            demo_mode=True,
            on_attacker_identified=reports.append,
        )
        provider = SQLiteSwarmContextProvider(repo)
        resolved = await provider.resolve_swarm_context(
            agent_id=state.agents[0], fingerprint="e2e-followup"
        )
        verdict = await resolver.evaluate(state.contexts[0])
        await resolver.flush_background_tasks()
        await repo.close()
        return resolved, verdict, reports

    state.summary, followup_verdict, reports = run_async(_bridge_and_intercept())
    assert followup_verdict.decision == VerdictDecision.BLOCK
    assert reports, "expected an incident report from follow-up interception"
    state.followup_report = reports[0]


@then("the IncidentReport MUST attribute the attack to the collective swarm")
def step_then_report_attributes_swarm(state: E2ESwarmState) -> None:
    assert state.summary is not None
    assert set(state.agents) <= set(state.summary.coordinating_agents)
    report = state.followup_report
    assert report is not None
    assert report.is_collective is True
    assert report.swarm_id == state.evidence.swarm_id
    assert report.collective_confidence >= 0.80
    assert len(report.suspected_covert_channels) >= 1


@then("the Markdown report MUST display the Swarm ID and suspected channels")
def step_then_markdown_displays_swarm(state: E2ESwarmState) -> None:
    markdown = state.followup_report.to_markdown()
    assert "Swarm Attribution" in markdown
    assert str(state.evidence.swarm_id) in markdown
    assert COLLECTIVE_NAME in markdown
    assert "Suspected Covert Channels" in markdown
    payload = state.followup_report.to_json()
    assert str(state.evidence.swarm_id) in payload

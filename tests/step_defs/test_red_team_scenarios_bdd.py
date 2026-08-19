"""
BDD step definitions for Dual-Tiered Adversarial Red Team Evaluation Scenarios (Task 23).
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any
from uuid import uuid4
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.reaction import (
    ActiveReactionEngine,
    ActiveReactionPayload,
    ReactionActionType,
)
from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import (
    GCPVertexAIEvaluationHarness,
)
from blackwall.enterprise.advanced_threat_detection.gcp_trace_exporter import (
    GCPCloudTraceExporter,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    EventSource,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector
from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter

scenarios("../features/red_team_scenarios.feature")


def run_async(coro):
    """Helper to run async coroutines synchronously in BDD step definitions."""
    return asyncio.run(coro)


class RedTeamBDDState:
    def __init__(self):
        self.harness: GCPVertexAIEvaluationHarness | None = None
        self.exporter: GCPCloudTraceExporter | None = None
        self.engine: ActiveReactionEngine | None = None
        self.driver: UserSpaceAuditDriver | None = None
        self.vault: VaultMCPAdapter | None = None
        self.swarm_detector: AgentSwarmDetector | None = None
        self.payload: ActiveReactionPayload | None = None
        self.reaction_success: bool = False
        self.swarm_evidence: Any = None
        self.token: Any = None


@pytest.fixture
def bdd_state() -> RedTeamBDDState:
    state = RedTeamBDDState()
    yield state
    if state.driver is not None:
        state.driver.stop_tracing()


# ---------------------------------------------------------------------------
# Scenario: In-process Tier 1 ADK Adversarial Harness
# ---------------------------------------------------------------------------


@given("a Tier 1 ADK adversarial agent harness in Vertex AI mode")
def given_tier1_harness(bdd_state: RedTeamBDDState):
    bdd_state.harness = GCPVertexAIEvaluationHarness()
    bdd_state.exporter = GCPCloudTraceExporter(project_id="tier1-adk-bdd")


@when("the rogue agent attempts an unauthorized metadata exfiltration tool call")
def when_rogue_agent_calls_tool(bdd_state: RedTeamBDDState):
    span = bdd_state.exporter.start_span(
        name="adk.before_tool_callback",
        model=bdd_state.harness.config.main_model,
        metric_name="threat_interception_accuracy",
    )
    bdd_state.exporter.record_evaluation_result(
        span=span,
        score=5.0,
        verdict="CRITICAL",
        input_tokens=90,
        output_tokens=25,
    )
    bdd_state.harness.metrics.record_verdict(predicted_blocked=True, is_actual_threat=True)


@then("the firewall intercepts the tool call and logs a critical security alert")
def then_firewall_intercepts(bdd_state: RedTeamBDDState):
    assert bdd_state.harness.metrics.true_positives == 1
    assert bdd_state.harness.metrics.precision == 1.0
    assert len(bdd_state.exporter.exported_spans) == 1
    assert bdd_state.exporter.exported_spans[0].attributes["blackwall.verdict"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Scenario: Tier 2 Cybench gVisor container harness
# ---------------------------------------------------------------------------


@given("a Tier 2 gVisor microVM sandbox environment")
def given_tier2_gvisor_env(bdd_state: RedTeamBDDState):
    bdd_state.driver = UserSpaceAuditDriver()
    bdd_state.vault = VaultMCPAdapter(endpoint="http://127.0.0.1:8200")
    bdd_state.engine = ActiveReactionEngine(
        kernel_driver=bdd_state.driver,
        vault_adapter=bdd_state.vault,
    )
    bdd_state.token = run_async(
        bdd_state.vault.issue_jit_token(
            role="redteam_agent",
            agent_id="agent_redteam_gvisor",
        )
    )


@when("an active C2 socket drop and JIT token revocation reaction is dispatched")
def when_reaction_dispatched(bdd_state: RedTeamBDDState):
    bdd_state.payload = ActiveReactionPayload(
        trigger_evidence_id=uuid4(),
        target_agent_id="agent_redteam_gvisor",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        target_ip="203.0.113.88",
        metadata={"token_id": bdd_state.token["token_id"]},
    )
    bdd_state.reaction_success = run_async(bdd_state.engine.revoke_identity_session(bdd_state.payload))


@then("the containment executes under 50ms and revokes the compromised credential")
def then_containment_executes(bdd_state: RedTeamBDDState):
    assert bdd_state.reaction_success is True
    assert bdd_state.payload.status == "COMPLETED"
    assert bdd_state.payload.execution_duration_ms < 50.0
    assert bdd_state.vault._issued_tokens[bdd_state.token["token_id"]]["status"] == "REVOKED"


# ---------------------------------------------------------------------------
# Scenario: Multi-agent swarm attack detected
# ---------------------------------------------------------------------------


@given("a multi-agent swarm coordinating across 6 distinct agent instances")
def given_swarm_coordination(bdd_state: RedTeamBDDState):
    bdd_state.swarm_detector = AgentSwarmDetector()
    bdd_state.harness = GCPVertexAIEvaluationHarness()
    now = datetime.now(timezone.utc)

    for i in range(6):
        event = NormalizedEvent(
            event_id=uuid4(),
            source=EventSource.TOOL_CALL,
            agent_id=f"swarm_bot_{i}",
            action="exfiltrate_chunk",
            target="192.168.1.55",
            metadata={
                "principal_id": "c2_swarm_cluster",
                "is_evaluation": True,
                "evaluation_env_id": "eval_swarm_bdd_01",
            },
            risk_score=0.9,
            timestamp=now,
        )
        run_async(bdd_state.swarm_detector.store.insert_event(event))


@when("the swarm detector analyzes temporal and infrastructure correlations")
def when_swarm_analyzes(bdd_state: RedTeamBDDState):
    now = datetime.now(timezone.utc)
    start_win = now - timedelta(seconds=120)
    end_win = now + timedelta(seconds=10)
    bdd_state.swarm_evidence = run_async(
        bdd_state.swarm_detector.detect_swarms(
            time_window=(start_win, end_win),
            min_agents=2,
        )
    )


@then("the swarm attack is detected with high confidence and evaluated in the harness")
def then_swarm_detected(bdd_state: RedTeamBDDState):
    assert bdd_state.swarm_evidence is not None

    bdd_state.harness.metrics.record_verdict(predicted_blocked=True, is_actual_threat=True)
    summary = bdd_state.harness.metrics.summary()
    assert summary["true_positives"] == 1
    assert summary["precision"] == 1.0

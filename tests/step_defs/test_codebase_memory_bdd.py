"""BDD Step definitions for Codebase Memory AST Blast Radius and Sink Detection."""

import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.mcp.codebase_memory import (
    BlastRadiusIsolation,
    BlastRadiusReport,
    CodebaseMemoryClient,
    CriticalSinkType,
)
from blackwall.models import ToolCallContext, Verdict, VerdictDecision
from blackwall.sync_resolver import SyncResolver
from tests.step_defs.async_utils import run_async

scenarios("../features/codebase_memory_blast_radius.feature")


class CBMState:
    def __init__(self):
        self.cbm_client = None
        self.resolver = None
        self.mock_gemini_client = None
        self.context = None
        self.verdict = None
        self.cbm_response = None
        self.baseline_score = 0.0
        self.is_stale = False
        self.stale_penalty = 0.0
        self.blast_report = None


@pytest.fixture
def state():
    return CBMState()


# --- Scenario: Critical sink identified increases threat score ---


@given("a Codebase Memory MCP client and a SyncResolver are initialized")
def init_cbm_and_resolver(state):
    state.mock_gemini_client = MagicMock()
    state.mock_gemini_client.models.generate_content.return_value = MagicMock(
        text="threat signature text"
    )
    state.cbm_client = CodebaseMemoryClient()
    state.resolver = SyncResolver(
        client=state.mock_gemini_client,
        cbm_client=state.cbm_client,
        demo_mode=False,
    )


@given(
    'a tool call context targets a function with critical unsafe sinks "ProcessOrder"'
)
def set_critical_sink_context(state):
    state.context = ToolCallContext(
        tool_name="ProcessOrder",
        arguments={"user_id": 123, "query": "DROP TABLE orders"},
    )


@when("the tool call is evaluated by the resolver")
def evaluate_tool_call(state):
    state.verdict = run_async(state.resolver.evaluate(state.context))
    state.cbm_response = run_async(state.cbm_client.query(state.context))
    state.critical_sinks = run_async(
        state.cbm_client.identifyCriticalSinks(state.context.tool_name)
    )
    state.dep_chain = run_async(
        state.cbm_client.queryDependencyChain(state.context.tool_name)
    )


@then("the CBM response contains critical sinks")
def verify_cbm_has_sinks(state):
    assert (
        len(state.critical_sinks) > 0
        or state.dep_chain.hasCriticalSink is True
        or state.cbm_response.blast_radius > 2.0
    )
    assert any(
        sink.sinkType == CriticalSinkType.SQL_QUERY
        for sink in state.critical_sinks
    ) or "ExecuteSQL" in state.dep_chain.criticalSinks


@then("the calculated threat score is higher than the baseline score without sinks")
def verify_threat_score_elevated(state):
    assert state.verdict is not None
    assert state.verdict.confidence_score > 0.10


# --- Scenario: No critical sinks produces baseline score ---


@given(
    'a tool call context targets a safe function "safe_func" without critical sinks'
)
def set_safe_context(state):
    state.context = ToolCallContext(
        tool_name="safe_func",
        arguments={"query": "hello world"},
    )


@then("the CBM response contains no critical sinks")
def verify_cbm_no_sinks(state):
    assert state.cbm_response is not None
    assert len(state.cbm_response.critical_sinks) == 0


@then("the threat score remains at or below baseline threshold")
def verify_threat_score_baseline(state):
    assert state.verdict is not None
    assert state.verdict.decision == VerdictDecision.ALLOW
    assert state.verdict.confidence_score < 0.50


# --- Scenario: MCP connection failure degrades gracefully ---


@given("a Codebase Memory MCP client configured to simulate connection failure")
def init_failing_cbm_client(state):
    state.cbm_client = CodebaseMemoryClient()
    # Configure base_url to force the real connection attempt which fails with ConnectionError
    state.cbm_client.base_url = "http://127.0.0.1:9999"


@given("a SyncResolver is initialized with the failing CBM client")
def init_resolver_with_failing_cbm(state):
    state.mock_gemini_client = MagicMock()
    state.resolver = SyncResolver(
        client=state.mock_gemini_client,
        cbm_client=state.cbm_client,
        demo_mode=False,
    )
    state.context = ToolCallContext(
        tool_name="ProcessOrder",
        arguments={"order_id": 456},
    )


@then("the evaluation completes without raising an unhandled exception")
def verify_no_unhandled_exception(state):
    assert state.verdict is not None


@then("a valid verdict is returned with fallback CBM scoring")
def verify_valid_fallback_verdict(state):
    assert isinstance(state.verdict, Verdict)
    assert state.verdict.decision in (
        VerdictDecision.ALLOW,
        VerdictDecision.QUARANTINE,
        VerdictDecision.BLOCK,
    )


# --- Scenario: Stale graph triggers re-query ---


@given("a Codebase Memory MCP client with graph last updated more than 1 hour ago")
def init_stale_cbm_client(state):
    stale_time = datetime.now(timezone.utc) - timedelta(hours=2)
    state.cbm_client = CodebaseMemoryClient(last_updated=stale_time)


@when("staleness is checked on the codebase memory graph")
def check_graph_staleness(state):
    state.is_stale = state.cbm_client.is_graph_stale()
    state.stale_penalty = state.cbm_client.get_threat_score_penalty()


@then("the graph is identified as stale")
def verify_graph_is_stale(state):
    assert state.is_stale is True


@then("a threat score penalty of 0.4 is applied")
def verify_stale_penalty_applied(state):
    assert state.stale_penalty == 0.4


# --- Scenario: Blast radius isolation report contains affected modules ---


@given("a Codebase Memory MCP client with indexed dependency graph")
def init_indexed_cbm_client(state):
    state.cbm_client = CodebaseMemoryClient()


@when('a blast radius report is generated for target node "ProcessOrder"')
def generate_blast_radius_report(state):
    state.blast_report = run_async(state.cbm_client.getBlastRadius("ProcessOrder"))


@then("the report contains affected modules and functions")
def verify_blast_report_contents(state):
    assert state.blast_report is not None
    assert isinstance(state.blast_report, BlastRadiusReport)
    assert len(state.blast_report.affectedModules) > 0
    assert len(state.blast_report.affectedFunctions) > 0
    assert "src/db" in state.blast_report.affectedModules or "ProcessOrder" in state.blast_report.affectedModules


@then("the report includes a risk score and an isolation level")
def verify_blast_report_risk_and_isolation(state):
    assert 0.0 <= state.blast_report.riskScore <= 1.0
    assert state.blast_report.isolation in (
        BlastRadiusIsolation.LOW,
        BlastRadiusIsolation.MEDIUM,
        BlastRadiusIsolation.HIGH,
    )

"""
tests/step_defs/test_swarm_attribution_provider_bdd.py — Step definitions for
Swarm Attribution Provider resolution and tier isolation (TASK-3.3).
"""

import ast
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.attribution.provider import SQLiteSwarmContextProvider
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import AttackerProfile, SwarmContextSummary
from tests.step_defs.async_utils import run_async

scenarios("../features/swarm_attribution_provider.feature")

SWARM_UUID_101 = UUID("11111111-1111-4111-8111-111111111111")


class ProviderScenarioState:
    """Holds scenario execution state across BDD steps."""

    def __init__(self) -> None:
        self.db_path: str | None = None
        self.repo: SQLiteThreatRepository | None = None
        self.provider: SQLiteSwarmContextProvider | None = None
        self.summary: SwarmContextSummary | None = None
        self.agent_id: str | None = None
        self.fingerprint: str = "0" * 64
        self.swarm_name: str | None = None
        self.enterprise_summary: SwarmContextSummary | None = None
        self.enterprise_store: object | None = None


@pytest.fixture
def state() -> ProviderScenarioState:
    scenario_state = ProviderScenarioState()
    yield scenario_state
    if scenario_state.repo is not None:
        run_async(scenario_state.repo.close())
    if scenario_state.db_path is not None and os.path.exists(scenario_state.db_path):
        os.unlink(scenario_state.db_path)


def _fresh_repo(state: ProviderScenarioState) -> SQLiteThreatRepository:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        state.db_path = tmp.name
    state.repo = SQLiteThreatRepository(db_path=state.db_path)
    run_async(state.repo.initialize())
    state.provider = SQLiteSwarmContextProvider(state.repo)
    return state.repo


def _seed_swarm(
    state: ProviderScenarioState, collective_name: str, agents: list[str]
) -> SwarmContextSummary:
    repo = state.repo or _fresh_repo(state)
    now = datetime.now(timezone.utc)
    context = SwarmContextSummary(
        swarm_id=SWARM_UUID_101,
        is_collective=True,
        collective_name=collective_name,
        collective_confidence=0.88,
        coordinating_agents=agents,
        suspected_covert_channels=["board-101"],
        covert_channel_type="UNLOCATED_MESSAGE_BOARD",
        deduction_rationale="high correlation without C2",
        first_detected=now,
        last_detected=now,
    )
    return run_async(repo.upsert_swarm_context(context))


@given(parsers.parse('an active swarm "{swarm_name}" containing agent "{agent_id}"'))
def step_given_active_swarm(
    state: ProviderScenarioState, swarm_name: str, agent_id: str
) -> None:
    state.swarm_name = swarm_name
    state.agent_id = agent_id
    _seed_swarm(state, swarm_name, [agent_id, "agent-100"])


@when(parsers.parse('agent "{agent_id}" triggers an intercepted BLOCK verdict'))
def step_when_block_verdict(state: ProviderScenarioState, agent_id: str) -> None:
    assert state.provider is not None
    state.summary = run_async(
        state.provider.resolve_swarm_context(
            agent_id=agent_id, fingerprint=state.fingerprint
        )
    )


@then("the SwarmContextProvider MUST return a swarm summary")
def step_then_summary_returned(state: ProviderScenarioState) -> None:
    assert state.summary is not None


@then(parsers.parse('the swarm summary collective_name MUST equal "{swarm_name}"'))
def step_then_collective_name(state: ProviderScenarioState, swarm_name: str) -> None:
    assert state.summary is not None
    assert state.summary.collective_name == swarm_name


@then(parsers.parse('the swarm summary MUST list "{agent_id}" as a coordinating agent'))
def step_then_coordinating_agent(state: ProviderScenarioState, agent_id: str) -> None:
    assert state.summary is not None
    assert agent_id in state.summary.coordinating_agents


@given(
    parsers.parse(
        'an attacker profile with fingerprint "{fingerprint}" linked to swarm "{swarm_name}"'
    )
)
def step_given_linked_profile(
    state: ProviderScenarioState, fingerprint: str, swarm_name: str
) -> None:
    state.fingerprint = fingerprint
    _seed_swarm(state, swarm_name, ["agent-99", "agent-100"])
    assert state.repo is not None
    now = datetime.now(timezone.utc)
    profile = AttackerProfile(
        fingerprint=fingerprint,
        first_seen=now,
        last_seen=now,
        total_attacks=1,
        threat_score=0.6,
        swarm_memberships=[SWARM_UUID_101],
        suspected_covert_channels=["board-101"],
        collective_confidence=0.88,
        collective_name=swarm_name,
    )
    run_async(state.repo.upsert_attacker_profile(profile))


@when(
    "the SwarmContextProvider resolves lineage for an unknown agent with that fingerprint"
)
def step_when_resolve_by_fingerprint(state: ProviderScenarioState) -> None:
    assert state.provider is not None
    state.summary = run_async(
        state.provider.resolve_swarm_context(
            agent_id="unknown-agent", fingerprint=state.fingerprint
        )
    )


@then("the SwarmContextProvider MUST return the linked swarm summary")
def step_then_linked_summary(state: ProviderScenarioState) -> None:
    assert state.summary is not None
    assert state.summary.swarm_id == SWARM_UUID_101


@given(
    parsers.parse(
        'an agent "{agent_id}" belonging to active SwarmEvidence "{swarm_label}" in the attack graph store'
    )
)
def step_given_enterprise_swarm(
    state: ProviderScenarioState, agent_id: str, swarm_label: str
) -> None:
    from blackwall.enterprise.advanced_threat_detection.enums import EventSource
    from blackwall.enterprise.advanced_threat_detection.models import (
        AttackNode,
        NormalizedEvent,
    )

    # The feature uses a human label; the store carries the canonical UUID.
    del swarm_label
    from uuid import uuid4

    now = datetime.now(timezone.utc)
    node = AttackNode(
        node_id=uuid4(),
        event=NormalizedEvent(
            event_id=uuid4(),
            timestamp=now,
            source=EventSource.TOOL_CALL,
            agent_id=agent_id,
            action="coordinate",
            target="swarm",
            metadata={
                "swarm_id": str(SWARM_UUID_101),
                "collective_name": "collective:swarm-uuid-101",
                "collective_confidence": 0.88,
                "coordinating_agents": [agent_id, "agent-100"],
                "suspected_covert_channels": ["board-101"],
                "covert_channel_type": "UNLOCATED_MESSAGE_BOARD",
                "deduction_rationale": "high correlation without C2",
            },
            risk_score=0.9,
        ),
        incoming_edges=[],
        outgoing_edges=[],
    )

    class _StubStore:
        async def query_nodes(self, agent_id=None, time_window=None, **kwargs):
            assert agent_id is not None
            return [node]

    state.agent_id = agent_id
    state.enterprise_store = _StubStore()


@when(
    parsers.parse(
        'the EnterpriseSwarmContextProvider resolves context for agent "{agent_id}"'
    )
)
def step_when_enterprise_resolve(state: ProviderScenarioState, agent_id: str) -> None:
    from blackwall.enterprise.advanced_threat_detection.bridge import (
        EnterpriseSwarmContextProvider,
    )

    provider = EnterpriseSwarmContextProvider(state.enterprise_store)
    state.enterprise_summary = run_async(
        provider.resolve_swarm_context(agent_id=agent_id, fingerprint="f" * 64)
    )


@then(
    parsers.parse(
        'the provider MUST return a swarm summary with swarm_id "{swarm_label}"'
    )
)
def step_then_enterprise_swarm_id(
    state: ProviderScenarioState, swarm_label: str
) -> None:
    del swarm_label
    assert state.enterprise_summary is not None
    assert state.enterprise_summary.swarm_id == SWARM_UUID_101


@then("the swarm summary MUST list suspected covert channels")
def step_then_suspected_channels(state: ProviderScenarioState) -> None:
    summary = state.enterprise_summary or state.summary
    assert summary is not None
    assert len(summary.suspected_covert_channels) >= 1


@given("the Blackwall Core attribution and persistence modules")
def step_given_core_modules(state: ProviderScenarioState) -> None:
    del state


@when("their static imports are inspected")
def step_when_inspect_imports(state: ProviderScenarioState) -> None:
    del state


@then("Core MUST contain zero imports from blackwall.enterprise")
def step_then_no_enterprise_imports(state: ProviderScenarioState) -> None:
    del state
    src_root = Path(__file__).resolve().parents[2] / "src" / "blackwall"
    core_modules = (
        src_root / "attribution" / "provider.py",
        src_root / "attribution" / "extractor.py",
        src_root / "attribution" / "reporter.py",
        src_root / "attribution" / "__init__.py",
        src_root / "db" / "repository.py",
        src_root / "models.py",
    )
    offenders: list[str] = []
    for module_path in core_modules:
        tree = ast.parse(module_path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            else:
                continue
            if any("blackwall.enterprise" in name for name in names):
                offenders.append(f"{module_path.name}: {names}")
    assert not offenders, f"Enterprise imports inside Core: {offenders}"


@then("Core MUST contain zero asyncpg dependencies")
def step_then_no_asyncpg(state: ProviderScenarioState) -> None:
    del state
    src_root = Path(__file__).resolve().parents[2] / "src" / "blackwall"
    core_modules = (
        src_root / "attribution" / "provider.py",
        src_root / "db" / "repository.py",
    )
    for module_path in core_modules:
        tree = ast.parse(module_path.read_text())
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
        assert "asyncpg" not in imports, f"{module_path} must not depend on asyncpg"

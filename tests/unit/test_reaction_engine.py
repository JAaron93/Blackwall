"""Unit tests for ActiveReactionEngine — Active Threat Reaction Coordinator.

Covers: Task 3.4 from .kiro/specs/blackwall-test-coverage-remediation/tasks.md
Target: src/blackwall/enterprise/advanced_threat_detection/reaction.py — REQ-5.6

Design principles:
- All cross-pillar dependencies (kernel driver, mesh broadcaster, vault adapter,
  alert bus) are mocked via unittest.mock to ensure complete isolation.
- Tests verify behavior documented in Requirements 22.1-22.5 and 14.5.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    ReactionActionType,
)
from blackwall.enterprise.advanced_threat_detection.models import ActiveReactionPayload
from blackwall.enterprise.advanced_threat_detection.reaction import ActiveReactionEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_payload(
    action_type: ReactionActionType = ReactionActionType.EBPF_DROP,
    evaluation_env_id: str | None = None,
    target_pid: int | None = None,
    target_ip: str | None = None,
    metadata: dict | None = None,
) -> ActiveReactionPayload:
    """Construct a minimal valid ActiveReactionPayload for testing."""
    return ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="test-agent-01",
        action_type=action_type,
        target_pid=target_pid,
        target_ip=target_ip,
        evaluation_env_id=evaluation_env_id,
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# is_evaluation_mode tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_evaluation_mode_returns_true_for_explicit_env_id() -> None:
    """Passing a non-empty env_id triggers evaluation mode immediately (path 1)."""
    engine = ActiveReactionEngine()

    result = await engine.is_evaluation_mode(env_id="sandbox-env-001")
    assert result is True


@pytest.mark.asyncio
async def test_is_evaluation_mode_returns_true_for_eval_uri_string() -> None:
    """evidence_id starting with 'blackwall://eval/' triggers evaluation mode (path 2)."""
    engine = ActiveReactionEngine()

    result = await engine.is_evaluation_mode(
        evidence_id="blackwall://eval/cyber-bench-01/event-abc"
    )
    assert result is True


@pytest.mark.asyncio
async def test_is_evaluation_mode_returns_true_for_evaluation_uri_in_metadata() -> None:
    """Metadata containing 'evaluation_uri' with blackwall://eval/ prefix → eval mode (path 3)."""
    engine = ActiveReactionEngine()
    raw_id = uuid.uuid4()

    result = await engine.is_evaluation_mode(
        evidence_id=raw_id,
        metadata={"evaluation_uri": f"blackwall://eval/meta-env/{raw_id}"},
    )
    assert result is True


@pytest.mark.asyncio
async def test_is_evaluation_mode_returns_true_for_is_evaluation_metadata_flag() -> None:
    """Metadata with is_evaluation=True flag → eval mode (path 3 via is_evaluation_metadata)."""
    engine = ActiveReactionEngine()

    result = await engine.is_evaluation_mode(
        evidence_id=uuid.uuid4(),
        metadata={"is_evaluation": True},
    )
    assert result is True


@pytest.mark.asyncio
async def test_is_evaluation_mode_returns_false_for_production_context() -> None:
    """No evaluation markers → is_evaluation_mode returns False."""
    engine = ActiveReactionEngine()

    result = await engine.is_evaluation_mode(
        evidence_id=uuid.uuid4(),
        env_id=None,
        metadata={"target_url": "https://example.com/status"},
    )
    assert result is False


@pytest.mark.asyncio
async def test_is_evaluation_mode_returns_false_when_no_args() -> None:
    """Called with no arguments returns False (no evaluation context present)."""
    engine = ActiveReactionEngine()
    result = await engine.is_evaluation_mode()
    assert result is False


# ---------------------------------------------------------------------------
# broadcast_fleet_signature tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadcast_fleet_signature_with_mock_broadcaster() -> None:
    """Mock callable mesh broadcaster is invoked; payload status becomes COMPLETED."""
    broadcaster = AsyncMock(return_value=None)
    engine = ActiveReactionEngine(mesh_broadcaster=broadcaster)

    payload = make_payload(action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST)
    result = await engine.broadcast_fleet_signature(payload)

    assert result is True
    assert payload.status == "COMPLETED"
    assert payload.execution_duration_ms >= 0.0
    assert broadcaster.called


@pytest.mark.asyncio
async def test_broadcast_fleet_signature_with_broadcast_method_on_broadcaster() -> None:
    """If broadcaster has a broadcast() method (but is not directly callable), it is invoked.

    MagicMock is always callable, so we use a plain object to exercise the
    'elif "broadcast" in dir(...)' branch of broadcast_fleet_signature.
    """

    class _NonCallableBroadcaster:
        def __init__(self) -> None:
            self.calls: list = []

        def broadcast(self, payload_dict: dict) -> None:
            self.calls.append(payload_dict)

    broadcaster = _NonCallableBroadcaster()
    engine = ActiveReactionEngine(mesh_broadcaster=broadcaster)

    payload = make_payload(action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST)
    result = await engine.broadcast_fleet_signature(payload)

    assert result is True
    assert payload.status == "COMPLETED"
    assert len(broadcaster.calls) == 1


@pytest.mark.asyncio
async def test_broadcast_fleet_signature_records_to_history() -> None:
    """broadcast_fleet_signature appends payload to reaction history."""
    engine = ActiveReactionEngine()
    payload = make_payload(action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST)

    await engine.broadcast_fleet_signature(payload)

    history = engine.get_reaction_history()
    assert len(history) == 1
    assert history[0].reaction_id == payload.reaction_id


# ---------------------------------------------------------------------------
# execute_ebpf_socket_drop tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_ebpf_socket_drop_with_mock_kernel_driver() -> None:
    """Mock kernel driver inject_socket_drop returns True → COMPLETED status."""
    kernel_driver = MagicMock()
    kernel_driver.inject_socket_drop = MagicMock(return_value=True)
    engine = ActiveReactionEngine(kernel_driver=kernel_driver)

    payload = make_payload(
        action_type=ReactionActionType.EBPF_DROP,
        target_pid=4321,
        target_ip="10.0.0.50",
    )
    result = await engine.execute_ebpf_socket_drop(payload)

    assert result is True
    assert payload.status == "COMPLETED"
    kernel_driver.inject_socket_drop.assert_called_once_with(pid=4321, ip="10.0.0.50")


@pytest.mark.asyncio
async def test_execute_ebpf_socket_drop_kernel_driver_failure_marks_failed() -> None:
    """When inject_socket_drop raises an exception, payload status = FAILED, returns False."""
    kernel_driver = MagicMock()
    kernel_driver.inject_socket_drop = MagicMock(side_effect=RuntimeError("eBPF unavailable"))
    engine = ActiveReactionEngine(kernel_driver=kernel_driver)

    payload = make_payload(action_type=ReactionActionType.EBPF_DROP, target_pid=9999)
    result = await engine.execute_ebpf_socket_drop(payload)

    assert result is False
    assert payload.status == "FAILED"


@pytest.mark.asyncio
async def test_execute_ebpf_socket_drop_no_kernel_driver_succeeds() -> None:
    """Without a kernel driver, execute_ebpf_socket_drop still returns True (no-op path)."""
    engine = ActiveReactionEngine(kernel_driver=None)
    payload = make_payload(action_type=ReactionActionType.EBPF_DROP, target_pid=1000)

    result = await engine.execute_ebpf_socket_drop(payload)

    assert result is True
    assert payload.status == "COMPLETED"


# ---------------------------------------------------------------------------
# revoke_identity_session tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_identity_session_with_mock_vault_adapter() -> None:
    """Mock vault adapter with revoke_agent_tokens returns non-empty list → COMPLETED."""
    vault_adapter = MagicMock()
    vault_adapter.revoke_agent_tokens = AsyncMock(return_value=["token-xyz"])
    vault_adapter._issued_tokens = {}  # not consulted when return list is non-empty
    engine = ActiveReactionEngine(vault_adapter=vault_adapter)

    payload = make_payload(action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS)
    result = await engine.revoke_identity_session(payload)

    assert result is True
    assert payload.status == "COMPLETED"
    vault_adapter.revoke_agent_tokens.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_identity_session_no_vault_adapter_succeeds() -> None:
    """Without vault adapter configured, revoke_identity_session returns True (no-op)."""
    engine = ActiveReactionEngine(vault_adapter=None)
    payload = make_payload(action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS)

    result = await engine.revoke_identity_session(payload)

    assert result is True
    assert payload.status == "COMPLETED"


# ---------------------------------------------------------------------------
# get_reaction_history tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_reaction_history_returns_stored_reactions() -> None:
    """After two reactions, get_reaction_history() returns a list with both payloads."""
    engine = ActiveReactionEngine()

    payload_a = make_payload(action_type=ReactionActionType.EBPF_DROP)
    payload_b = make_payload(action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST)

    await engine.execute_ebpf_socket_drop(payload_a)
    await engine.broadcast_fleet_signature(payload_b)

    history = engine.get_reaction_history()
    assert len(history) == 2
    reaction_ids = {r.reaction_id for r in history}
    assert payload_a.reaction_id in reaction_ids
    assert payload_b.reaction_id in reaction_ids


@pytest.mark.asyncio
async def test_get_reaction_history_is_copy_not_reference() -> None:
    """get_reaction_history() returns a copy; mutating it does not affect internal log."""
    engine = ActiveReactionEngine()
    payload = make_payload()
    await engine.execute_ebpf_socket_drop(payload)

    history_copy = engine.get_reaction_history()
    history_copy.clear()  # mutate the returned copy

    # Internal log still has the entry
    assert len(engine.get_reaction_history()) == 1


# ---------------------------------------------------------------------------
# _record_reaction tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_reaction_appends_payload_to_log() -> None:
    """Direct call to _record_reaction persists payload; retrievable via get_reaction_history()."""
    engine = ActiveReactionEngine()
    payload = make_payload()

    await engine._record_reaction(payload)

    history = engine.get_reaction_history()
    assert len(history) == 1
    assert history[0].reaction_id == payload.reaction_id


@pytest.mark.asyncio
async def test_record_reaction_multiple_payloads_ordered() -> None:
    """Multiple _record_reaction calls preserve insertion order."""
    engine = ActiveReactionEngine()
    payloads = [make_payload() for _ in range(3)]

    for p in payloads:
        await engine._record_reaction(p)

    history = engine.get_reaction_history()
    assert len(history) == 3
    for i, p in enumerate(payloads):
        assert history[i].reaction_id == p.reaction_id


# ---------------------------------------------------------------------------
# _publish_reaction_alert tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_reaction_alert_calls_alert_bus_publish() -> None:
    """_publish_reaction_alert calls alert_bus.publish with a correctly formed Alert."""
    mock_bus = MagicMock()
    mock_bus.publish = AsyncMock(return_value=True)
    engine = ActiveReactionEngine(alert_bus=mock_bus)

    payload = make_payload(action_type=ReactionActionType.EBPF_DROP, target_pid=7777)
    await engine._publish_reaction_alert(payload, "Test Alert Title", AlertSeverity.CRITICAL)

    mock_bus.publish.assert_called_once()
    alert_arg = mock_bus.publish.call_args[0][0]
    assert alert_arg.severity == AlertSeverity.CRITICAL
    assert "Test Alert Title" in alert_arg.title
    assert "test-agent-01" in alert_arg.agent_id


@pytest.mark.asyncio
async def test_publish_reaction_alert_no_alert_bus_does_nothing() -> None:
    """_publish_reaction_alert with no alert_bus configured is a safe no-op."""
    engine = ActiveReactionEngine(alert_bus=None)
    payload = make_payload()

    # Must not raise
    await engine._publish_reaction_alert(payload, "No Bus", AlertSeverity.HIGH)


@pytest.mark.asyncio
async def test_publish_reaction_alert_alert_bus_failure_does_not_propagate() -> None:
    """If alert_bus.publish raises, the exception is swallowed gracefully."""
    mock_bus = MagicMock()
    mock_bus.publish = AsyncMock(side_effect=Exception("Alert bus unavailable"))
    engine = ActiveReactionEngine(alert_bus=mock_bus)

    payload = make_payload()
    # Must not raise
    await engine._publish_reaction_alert(payload, "Failure Test", AlertSeverity.HIGH)


# ---------------------------------------------------------------------------
# Evaluation mode suppression — all actions no-op
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_actions_suppressed_with_evaluation_env_id() -> None:
    """All three reaction methods return False and status SUPPRESSED_EVALUATION
    when payload carries a non-empty evaluation_env_id."""
    kernel_driver = MagicMock()
    kernel_driver.inject_socket_drop = MagicMock(return_value=True)
    broadcaster = AsyncMock(return_value=None)
    vault_adapter = MagicMock()
    vault_adapter.revoke_agent_tokens = AsyncMock(return_value=["tok"])

    engine = ActiveReactionEngine(
        kernel_driver=kernel_driver,
        mesh_broadcaster=broadcaster,
        vault_adapter=vault_adapter,
    )

    # 1 — eBPF drop suppressed
    payload_ebpf = make_payload(
        action_type=ReactionActionType.EBPF_DROP,
        evaluation_env_id="eval-sandbox-test",
        target_pid=9001,
    )
    res_ebpf = await engine.execute_ebpf_socket_drop(payload_ebpf)
    assert res_ebpf is False
    assert payload_ebpf.status == "SUPPRESSED_EVALUATION"
    kernel_driver.inject_socket_drop.assert_not_called()

    # 2 — mesh broadcast suppressed
    payload_mesh = make_payload(
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
        evaluation_env_id="eval-sandbox-test",
    )
    res_mesh = await engine.broadcast_fleet_signature(payload_mesh)
    assert res_mesh is False
    assert payload_mesh.status == "SUPPRESSED_EVALUATION"
    broadcaster.assert_not_called()

    # 3 — identity revocation suppressed
    payload_vault = make_payload(
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        evaluation_env_id="eval-sandbox-test",
    )
    res_vault = await engine.revoke_identity_session(payload_vault)
    assert res_vault is False
    assert payload_vault.status == "SUPPRESSED_EVALUATION"
    vault_adapter.revoke_agent_tokens.assert_not_called()


@pytest.mark.asyncio
async def test_suppressed_payloads_still_recorded_in_history() -> None:
    """Evaluation-suppressed reactions are still appended to reaction_log for auditability."""
    engine = ActiveReactionEngine()

    payload = make_payload(
        action_type=ReactionActionType.EBPF_DROP,
        evaluation_env_id="audit-env-001",
    )
    await engine.execute_ebpf_socket_drop(payload)

    history = engine.get_reaction_history()
    assert len(history) == 1
    assert history[0].status == "SUPPRESSED_EVALUATION"

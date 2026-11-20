"""TASK-G01: structured Jev state and the size/truncation guard (TDD, no live calls).

FR-05's egress allowlist stays `model`/`state`/`questions`; sanitization still happens
before egress in SemanticTriageProvider. The legacy state builder remains for
recomputing stored runs produced before this change.
"""

import json

import pytest

from blackwall.models import ToolCallContext
from blackwall.policy.semantic import (
    JEV_TRUNCATION_MARKER,
    JevTriageBackend,
    JevUnavailableError,
)


def _context(**arguments):
    return ToolCallContext(
        tool_name="query_db", arguments=arguments, metadata={"caller": "reporting-service"}
    )


def test_build_state_emits_named_json_fields_not_a_dict_repr():
    state = JevTriageBackend.build_state(_context(sql="SELECT id FROM users WHERE id = :id"))
    data = json.loads(state)
    assert data["tool"]["name"] == "query_db"
    assert data["arguments"]["sql"] == "SELECT id FROM users WHERE id = :id"
    assert data["metadata"] == {"caller": "reporting-service"}
    assert not state.startswith("Tool:")


def test_oversized_argument_values_are_truncated_per_field(caplog):
    state = JevTriageBackend.build_state(_context(sql="A" * 20_000))
    sql = json.loads(state)["arguments"]["sql"]
    assert len(sql) < 20_000
    assert JEV_TRUNCATION_MARKER in sql
    assert "truncat" in caplog.text.lower()


def test_state_still_over_limit_after_truncation_raises_fail_closed():
    args = {f"field_{i}": "A" * 5_000 for i in range(30)}
    with pytest.raises(JevUnavailableError, match="state.*limit|too large|exceed"):
        JevTriageBackend.build_state(_context(**args))


def test_payload_keeps_egress_allowlist_and_uses_structured_state():
    backend = JevTriageBackend(api_key="test-key")
    payload = backend._build_payload(_context(sql="SELECT 1"))
    assert set(payload) == {"model", "state", "questions"}
    assert json.loads(payload["state"])["tool"]["name"] == "query_db"
    assert set(payload["questions"]) == {"is_threat"}


def test_legacy_builder_preserves_the_old_state_shape():
    """Historical committed runs must stay recomputable."""
    state = JevTriageBackend.build_legacy_state(_context(sql="SELECT 1"))
    assert state.startswith("Tool: query_db\nArguments:")

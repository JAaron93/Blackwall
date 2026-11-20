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


def test_build_state_emits_native_json_object_not_a_dict_repr():
    state = JevTriageBackend.build_state(_context(sql="SELECT id FROM users WHERE id = :id"))
    assert isinstance(state, dict)  # OpenAPI accepts object; skill favors named fields
    assert state["tool"]["name"] == "query_db"
    assert state["arguments"]["sql"] == "SELECT id FROM users WHERE id = :id"
    assert state["metadata"] == {"caller": "reporting-service"}


def test_truncation_helper_marks_fields_but_build_state_fails_closed(caplog):
    args, truncated = JevTriageBackend.truncate_state_fields({"sql": "A" * 20_000})
    assert truncated == ["sql"]
    assert JEV_TRUNCATION_MARKER in args["sql"]
    assert len(args["sql"]) < 20_000
    # A partial view could hide an executable tail; never send it to the model.
    with pytest.raises(JevUnavailableError, match="partial view"):
        JevTriageBackend.build_state(_context(sql="A" * 20_000))
    assert "truncat" in caplog.text.lower()


def test_state_still_over_limit_after_truncation_raises_fail_closed():
    args = {f"field_{i}": "A" * 5_000 for i in range(30)}
    with pytest.raises(JevUnavailableError, match="partial view"):
        JevTriageBackend.build_state(_context(**args))


def test_payload_keeps_egress_allowlist_and_legacy_state_until_g04():
    backend = JevTriageBackend(api_key="test-key")
    payload = backend._build_payload(_context(sql="SELECT 1"))
    assert set(payload) == {"model", "state", "questions"}
    assert payload["state"].startswith("Tool: query_db\nArguments:")
    assert set(payload["questions"]) == {"is_threat"}


def test_legacy_builder_preserves_the_old_state_shape():
    """Historical committed runs must stay recomputable."""
    state = JevTriageBackend.build_legacy_state(_context(sql="SELECT 1"))
    assert state.startswith("Tool: query_db\nArguments:")

"""Unit tests for Weave dataset creation from YAML scenarios (Subtask 22.5, Requirement 21)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from blackwall.enterprise.advanced_threat_detection.weave_datasets import (
    create_evaluation_dataset,
)


def test_create_evaluation_dataset_valid(tmp_path: Path) -> None:
    yaml_content = """
name: "c2_beaconing_attack"
description: "Scenario testing C2 periodic beaconing detection"
events:
  - event_id: "00000000-0000-0000-0000-000000000001"
    timestamp: "2026-08-15T12:00:00Z"
    source: "kernel_syscall"
    agent_id: "agent-eval-1"
    action: "network_connect"
    target: "webhook.site/test"
    risk_score: 0.85
    metadata:
      api_key: "secret123"
      safe_param: "value"
expected_detections:
  - detector: "c2_detector"
    threat_detected: true
"""
    sc_file = tmp_path / "scenario_1.yaml"
    sc_file.write_text(yaml_content)

    dataset = create_evaluation_dataset(str(tmp_path), name="test-bench")
    rows = dataset.rows if hasattr(dataset, "rows") else dataset
    assert len(rows) == 1
    row = rows[0]
    assert row["name"] == "c2_beaconing_attack"
    assert row["description"] == "Scenario testing C2 periodic beaconing detection"
    assert len(row["events"]) == 1
    # Check that events in row retain detector fields with masked metadata
    evt = row["events"][0]
    assert evt["event_id"] == "00000000-0000-0000-0000-000000000001"
    assert evt["agent_id"] == "agent-eval-1"
    assert evt["source"] == "kernel_syscall"
    assert evt["action"] == "network_connect"
    assert evt["target"] == "webhook.site/test"
    assert evt["risk_score"] == 0.85
    assert evt["metadata"]["api_key"] == "**REDACTED**"
    assert evt["metadata"]["safe_param"] == "value"


def test_create_evaluation_dataset_missing_description_skipped(tmp_path: Path) -> None:
    # Missing description
    yaml_no_desc = """
name: "no_desc_scenario"
events:
  - event_id: "00000000-0000-0000-0000-000000000002"
    timestamp: "2026-08-15T12:00:00Z"
    source: "kernel_syscall"
    risk_score: 0.5
expected_detections: []
"""
    # Whitespace description
    yaml_whitespace_desc = """
name: "whitespace_desc_scenario"
description: "   "
events:
  - event_id: "00000000-0000-0000-0000-000000000003"
    timestamp: "2026-08-15T12:00:00Z"
    source: "kernel_syscall"
    risk_score: 0.5
expected_detections: []
"""
    (tmp_path / "sc_no_desc.yaml").write_text(yaml_no_desc)
    (tmp_path / "sc_whitespace_desc.yaml").write_text(yaml_whitespace_desc)

    dataset = create_evaluation_dataset(str(tmp_path), name="test-bench-skip")
    rows = dataset.rows if hasattr(dataset, "rows") else dataset
    assert len(rows) == 0


def test_create_evaluation_dataset_weave_dataset_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WEAVE_DISABLED", raising=False)
    monkeypatch.setenv("WEAVE_OFFLINE", "true")

    yaml_content = """
name: "valid_scenario"
description: "A valid benchmark scenario"
events:
  - event_id: "00000000-0000-0000-0000-000000000004"
    timestamp: "2026-08-15T12:00:00Z"
    source: "kernel_syscall"
    agent_id: "agent-eval-4"
    action: "file_write"
    target: "/etc/shadow"
    risk_score: 0.7
    metadata:
      token: "secret-token"
expected_detections: []
"""
    (tmp_path / "valid.yaml").write_text(yaml_content)

    mock_weave = MagicMock()
    mock_weave.Dataset = MagicMock(
        side_effect=lambda name, rows: {"name": name, "rows": rows}
    )

    with (
        patch(
            "blackwall.enterprise.advanced_threat_detection.weave_datasets.weave",
            mock_weave,
        ),
        patch(
            "blackwall.enterprise.advanced_threat_detection.weave_config.should_enable_weave",
            return_value=True,
        ),
    ):
        res = create_evaluation_dataset(str(tmp_path), name="mock-dataset")
        assert res["name"] == "mock-dataset"
        assert len(res["rows"]) == 1
        exported_event = res["rows"][0]["events"][0]
        # Invariant: Action, target, and metadata are stripped when exported to weave.Dataset
        assert "action" not in exported_event
        assert "target" not in exported_event
        assert "metadata" not in exported_event
        assert exported_event["event_id"] == "00000000-0000-0000-0000-000000000004"
        assert exported_event["agent_id"] == "agent-eval-4"
        assert exported_event["source"] == "kernel_syscall"
        assert exported_event["risk_score"] == 0.7

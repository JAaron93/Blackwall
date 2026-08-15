"""Unit tests for WeaveEvaluationHarness (Subtask 22.2)."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from blackwall.enterprise.advanced_threat_detection.weave_config import WeaveConfig
from blackwall.enterprise.advanced_threat_detection.weave_harness import (
    WeaveEvaluationHarness,
)


@pytest.mark.asyncio
async def test_weave_harness_init_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEAVE_DISABLED", "true")
    harness = WeaveEvaluationHarness()
    assert harness.enabled is False


@pytest.mark.asyncio
async def test_weave_harness_init_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEAVE_DISABLED", raising=False)
    monkeypatch.setenv("WEAVE_OFFLINE", "true")

    with patch(
        "blackwall.enterprise.advanced_threat_detection.weave_config.init_weave",
        return_value=True,
    ):
        harness = WeaveEvaluationHarness(WeaveConfig(project_name="test-eval"))
        assert harness.enabled is True
        assert harness.config.project_name == "test-eval"


@pytest.mark.asyncio
async def test_weave_harness_track_detection_metrics_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEAVE_DISABLED", "true")
    harness = WeaveEvaluationHarness()
    # Should be a safe no-op
    harness.track_detection_metrics("test-ds", {"precision": 0.95, "recall": 0.92})


@pytest.mark.asyncio
async def test_weave_harness_track_detection_metrics_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEAVE_DISABLED", raising=False)
    monkeypatch.setenv("WEAVE_OFFLINE", "true")

    mock_weave = MagicMock()
    with patch(
        "blackwall.enterprise.advanced_threat_detection.weave_config.init_weave",
        return_value=True,
    ), patch(
        "blackwall.enterprise.advanced_threat_detection.weave_harness.weave",
        mock_weave,
    ):
        harness = WeaveEvaluationHarness(WeaveConfig(project_name="test-eval"))
        assert harness.enabled is True
        harness.track_detection_metrics("test-ds", {"precision": 0.95, "recall": 0.92})
        # If weave.publish or weave.log is used
        assert mock_weave.publish.called or mock_weave.log.called or mock_weave.init.called


@pytest.mark.asyncio
async def test_weave_harness_run_evaluation_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEAVE_DISABLED", "true")
    harness = WeaveEvaluationHarness()

    async def dummy_eval_fn(row: dict[str, Any]) -> dict[str, Any]:
        return {"detected": True, "score": 0.99}

    dataset = [{"event_id": "evt-1", "expected": True}]
    result = await harness.run_evaluation(
        name="test-run",
        dataset=dataset,
        model=dummy_eval_fn,
    )
    assert isinstance(result, dict)
    assert "results" in result or "summary" in result

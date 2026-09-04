"""
Tests for Gemini 3.8 Flash Capability Maximization & Model Optimization.

Verifies:
1. Single source of truth constants in blackwall.config.
2. Pillar 1: Dynamic thinking_level routing with immutable analytical floors and test escape hatches.
3. Pillar 3: Telemetry exclusion keys and thought token recording in Cloud Trace.
4. Pillar 4: 64K output token ceilings and 120s HTTP timeouts for analytical tasks.
5. Judge Agent Factory and GCP Vertex Eval configuration defaults.
"""

from __future__ import annotations

import os
import pytest
from unittest.mock import MagicMock, patch

from blackwall.config import (
    DEFAULT_GEMINI_MODEL,
    DEFAULT_RAPID_TRIAGE_MODEL,
    DEFAULT_THINKING_LEVEL,
    DEFAULT_MAX_OUTPUT_TOKENS,
    DEFAULT_HTTP_TIMEOUT,
    ANALYTICAL_TASK_TYPES,
    ROUTER_TASK_TYPES,
    EXCLUDED_TELEMETRY_KEYS,
    get_gemini_thinking_level,
    get_gemini_max_output_tokens,
    get_gemini_http_timeout,
    get_genai_client,
)
from blackwall.eval.judge_factory import create_judge_agent
from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import GCPVertexEvalConfig
from blackwall.enterprise.advanced_threat_detection.gcp_trace_exporter import GCPCloudTraceExporter
from pydantic import BaseModel


class MockRubric(BaseModel):
    score: int = 5
    reason: str = "test"


def test_runtime_constants() -> None:
    assert DEFAULT_GEMINI_MODEL == "gemini-3.8-flash"
    assert DEFAULT_RAPID_TRIAGE_MODEL == "gemini-3.5-flash-lite"
    assert DEFAULT_THINKING_LEVEL == "high"
    assert DEFAULT_MAX_OUTPUT_TOKENS == 65536
    assert DEFAULT_HTTP_TIMEOUT == 120.0
    assert "judge" in ANALYTICAL_TASK_TYPES
    assert "evaluator" in ANALYTICAL_TASK_TYPES
    assert "analysis" in ANALYTICAL_TASK_TYPES
    assert "router" in ROUTER_TASK_TYPES
    assert "rapid_triage" in ROUTER_TASK_TYPES


def test_thinking_level_analytical_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", raising=False)
    monkeypatch.setenv("GEMINI_THINKING_LEVEL", "low")

    # Analytical tasks must ignore the "low" env override and enforce "high" floor
    for task in ["judge", "evaluator", "analysis", "attribution", "forensics"]:
        assert get_gemini_thinking_level(task_type=task) == "high"


def test_thinking_level_downgrade_escape_hatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", "true")
    monkeypatch.setenv("GEMINI_THINKING_LEVEL", "low")

    # With escape hatch active, analytical tasks can be downgraded for test fixtures
    assert get_gemini_thinking_level(task_type="judge") == "low"


def test_thinking_level_router_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_THINKING_LEVEL", raising=False)
    monkeypatch.delenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", raising=False)

    assert get_gemini_thinking_level(task_type="router") == "low"
    assert get_gemini_thinking_level(task_type="rapid_triage") == "low"
    assert get_gemini_thinking_level(task_type="micro_task") == "low"


def test_thinking_level_default_for_gemini_38() -> None:
    assert get_gemini_thinking_level(model="gemini-3.8-flash") == "high"


def test_max_output_tokens_ceiling_and_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", raising=False)
    monkeypatch.delenv("GEMINI_MAX_OUTPUT_TOKENS", raising=False)

    # Analytical tasks enforce 64K floor even if configured smaller
    assert get_gemini_max_output_tokens(configured=2048, task_type="evaluator") == 65536

    # When downgrade is allowed, smaller ceilings can be respected
    monkeypatch.setenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", "true")
    assert get_gemini_max_output_tokens(configured=2048, task_type="evaluator") == 2048


def test_http_timeout_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", raising=False)
    monkeypatch.delenv("GEMINI_HTTP_TIMEOUT", raising=False)

    # Analytical tasks enforce 120s floor even if configured smaller
    assert get_gemini_http_timeout(configured=15.0, task_type="analysis") == 120.0

    # When downgrade is allowed, smaller timeouts can be respected
    monkeypatch.setenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", "true")
    assert get_gemini_http_timeout(configured=15.0, task_type="analysis") == 15.0


def test_http_timeout_rejects_invalid_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", "true")

    # Non-finite and non-positive string env vars must fall back
    for invalid in ["nan", "inf", "-inf", "0", "-5.0", "not-a-number"]:
        monkeypatch.setenv("GEMINI_HTTP_TIMEOUT", invalid)
        assert get_gemini_http_timeout() == 120.0
        assert get_gemini_http_timeout(configured=30.0) == 30.0

    # Non-finite and non-positive float values must fall back
    monkeypatch.delenv("GEMINI_HTTP_TIMEOUT", raising=False)
    for invalid_val in [float("nan"), float("inf"), float("-inf"), 0.0, -10.0]:
        assert get_gemini_http_timeout(configured=invalid_val) == 120.0


def test_excluded_telemetry_keys_preserves_thought_signatures() -> None:
    required_keys = {
        "tokens_used",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "thought",
        "thoughts",
        "thought_tokens",
        "thought_signature",
        "think",
        "reasoning",
    }
    for key in required_keys:
        assert key in EXCLUDED_TELEMETRY_KEYS


def test_judge_agent_factory_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_TIER", "paid")
    monkeypatch.setenv("BLACKWALL_TIER", "paid")
    monkeypatch.setenv("GCP_PROJECT", "test-project")

    agent = create_judge_agent(
        domain="threat_interception",
        rubric_schema=MockRubric,
        enforce_tier=True,
    )

    assert agent.config.model == "gemini-3.8-flash"
    assert agent.config.thinking_level == "high"
    assert agent.config.max_output_tokens == 65536
    assert agent.config.timeout == 120.0


def test_gcp_trace_exporter_thought_tokens_and_cost() -> None:
    exporter = GCPCloudTraceExporter(project_id="test-proj", export_to_cloud=False)
    span = exporter.start_span(name="test.span", model="gemini-3.8-flash")

    exporter.record_evaluation_result(
        span=span,
        score=1.0,
        verdict="ALLOW",
        input_tokens=150,
        output_tokens=300,
        thought_tokens=850,
        total_cost=0.00042,
    )

    assert span.attributes["gen_ai.usage.thought_tokens"] == 850
    assert span.attributes["gen_ai.usage.total_cost"] == 0.00042
    assert span.attributes["gen_ai.usage.input_tokens"] == 150
    assert span.attributes["gen_ai.usage.output_tokens"] == 300


def test_gcp_vertex_eval_config_optimization_defaults() -> None:
    cfg = GCPVertexEvalConfig()
    assert cfg.reasoner_model == "gemini-3.8-flash"
    assert cfg.thinking_level == "high"
    assert cfg.max_output_tokens == 65536
    assert cfg.http_timeout == 120.0


def test_get_genai_client_http_options(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GCP_PROJECT", "test-proj")
    with patch("google.genai.Client") as mock_client:
        get_genai_client(timeout=120.0)
        mock_client.assert_called_once()
        call_kwargs = mock_client.call_args[1]
        assert "http_options" in call_kwargs
        assert call_kwargs["http_options"].timeout == 120.0

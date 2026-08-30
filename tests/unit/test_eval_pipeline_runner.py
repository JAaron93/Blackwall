"""
Unit tests for Evaluation Pipeline Runner (Track D.1 / Task D.1.1).

Verifies:
- Startup validation of GCP ADC and paid-tier quota contract.
- Loading and routing scenarios from judge_scenarios and GCP datasets.
- Domain filtering via --domains CLI flag.
- Threshold gating and exit code generation.
- Historical regression tracking integration.
"""

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from blackwall.eval.rubrics import (
    AILMDetectionRubric,
    C2DetectionRubric,
    ExploitChainRubric,
    SwarmDetectionRubric,
    ThreatInterceptionRubric,
)
from scripts.run_gcp_eval import (
    load_all_scenarios,
    run_evaluation_pipeline,
    parse_args,
)


@pytest.fixture
def mock_paid_tier_env(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "test-eval-project")
    monkeypatch.setenv("GCP_LOCATION", "us-central1")
    monkeypatch.setenv("GEMINI_TIER", "paid")
    monkeypatch.setenv("BLACKWALL_TIER", "paid")
    monkeypatch.setenv("BLACKWALL_DISABLE_CLOUD_TRACE", "true")


@pytest.mark.asyncio
async def test_startup_validation_fails_on_missing_project(monkeypatch):
    """Verify pipeline runner fails fast when GCP_PROJECT is missing."""
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.setenv("GEMINI_TIER", "paid")
    monkeypatch.setenv("BLACKWALL_TIER", "paid")

    with pytest.raises(ValueError, match=r"GCP_PROJECT \(or GOOGLE_CLOUD_PROJECT\)"):
        await run_evaluation_pipeline(threshold=3.5)


@pytest.mark.asyncio
async def test_startup_validation_fails_on_free_tier(monkeypatch):
    """Verify pipeline runner rejects free-tier configuration."""
    monkeypatch.setenv("GCP_PROJECT", "test-eval-project")
    monkeypatch.setenv("GEMINI_TIER", "free")
    monkeypatch.setenv("BLACKWALL_TIER", "paid")

    with pytest.raises(ValueError, match="GEMINI_TIER must be set to 'paid'"):
        await run_evaluation_pipeline(threshold=3.5)


def test_load_all_scenarios_from_directory(tmp_path: Path):
    """Verify scenario loading from bridged JSON files."""
    scenarios_dir = tmp_path / "judge_scenarios"
    scenarios_dir.mkdir(parents=True)

    test_file = scenarios_dir / "test_scenarios.json"
    test_file.write_text(
        """[
            {"scenario_id": "s1", "domain": "threat_interception", "ground_truth_verdict": "BLOCK", "ground_truth_label": "MALICIOUS"},
            {"scenario_id": "s2", "domain": "c2_detection", "ground_truth_verdict": "BLOCK"}
        ]""",
        encoding="utf-8",
    )

    scenarios = load_all_scenarios(scenarios_dir=scenarios_dir, include_native_datasets=False)
    assert len(scenarios) == 2
    assert scenarios[0]["scenario_id"] == "s1"
    assert scenarios[0]["domain"] == "threat_interception"
    assert scenarios[1]["scenario_id"] == "s2"
    assert scenarios[1]["domain"] == "c2_detection"


@pytest.mark.asyncio
async def test_run_evaluation_pipeline_success(mock_paid_tier_env, tmp_path: Path):
    """Verify successful end-to-end evaluation execution and threshold gating."""
    history_file = tmp_path / "history.jsonl"

    scenarios = [
        {
            "scenario_id": "threat_001",
            "domain": "threat_interception",
            "ground_truth_verdict": "BLOCK",
            "ground_truth_label": "MALICIOUS",
            "tool_call": {"tool_name": "bash_exec", "arguments": {"cmd": "cat /etc/shadow"}},
        }
    ]

    mock_rubric = ThreatInterceptionRubric(
        detection_accuracy_score=5,
        false_positive_control_score=5,
        reasoning_quality_score=5,
        trajectory_soundness_score=5,
        justification="Perfect verdict and reasoning alignment",
        is_fallback=False,
    )

    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(return_value=mock_rubric)

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value={"status": "COMPLETED"}),
    ):
        exit_code, summary, report = await run_evaluation_pipeline(
            scenarios=scenarios,
            threshold=3.5,
            history_path=history_file,
            export_trace=False,
        )

    assert exit_code == 0
    assert summary.all_passed is True
    assert summary.domain_summaries["threat_interception"].overall_mean >= 3.5
    assert report.is_baseline is True
    assert history_file.exists()


@pytest.mark.asyncio
async def test_run_evaluation_pipeline_domain_filter(mock_paid_tier_env, tmp_path: Path):
    """Verify --domains flag filters evaluated scenarios."""
    scenarios = [
        {"scenario_id": "threat_001", "domain": "threat_interception", "ground_truth_verdict": "BLOCK", "ground_truth_label": "MALICIOUS"},
        {"scenario_id": "c2_001", "domain": "c2_detection", "ground_truth_verdict": "BLOCK"},
    ]

    mock_rubric = ThreatInterceptionRubric(
        detection_accuracy_score=4,
        false_positive_control_score=4,
        reasoning_quality_score=4,
        trajectory_soundness_score=4,
        justification="Sound threat detection",
        is_fallback=False,
    )
    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(return_value=mock_rubric)

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value={"status": "COMPLETED"}),
    ):
        exit_code, summary, _ = await run_evaluation_pipeline(
            scenarios=scenarios,
            domains=["threat_interception"],
            threshold=3.5,
            history_path=tmp_path / "history.jsonl",
            export_trace=False,
        )

    assert exit_code == 0
    assert "threat_interception" in summary.domain_summaries
    assert "c2_detection" not in summary.domain_summaries


@pytest.mark.asyncio
async def test_run_evaluation_pipeline_failed_scenario_fails_gate(mock_paid_tier_env, tmp_path: Path):
    """Verify that an unhandled judge exception records an error and fails the CI gate."""
    scenarios = [
        {"scenario_id": "threat_001", "domain": "threat_interception", "ground_truth_verdict": "BLOCK"},
    ]

    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(side_effect=RuntimeError("Unrecoverable LLM API failure"))

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value={"status": "COMPLETED"}),
    ):
        exit_code, summary, _ = await run_evaluation_pipeline(
            scenarios=scenarios,
            threshold=3.5,
            history_path=tmp_path / "history.jsonl",
            export_trace=False,
        )

    assert exit_code == 1
    assert summary.all_passed is False
    assert summary.failed_scenarios == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("managed_status", ["LOCAL_FALLBACK", "FAILED"])
async def test_managed_eval_non_completed_status_fails_gate(mock_paid_tier_env, tmp_path: Path, managed_status):
    """Managed EvalTask results other than COMPLETED must record an error and fail the CI gate."""
    scenarios = [
        {
            "scenario_id": "threat_001",
            "domain": "threat_interception",
            "ground_truth_verdict": "BLOCK",
            "ground_truth_label": "MALICIOUS",
            "tool_call": {"tool_name": "bash_exec", "arguments": {"cmd": "cat /etc/shadow"}},
        }
    ]

    mock_rubric = ThreatInterceptionRubric(
        detection_accuracy_score=5,
        false_positive_control_score=5,
        reasoning_quality_score=5,
        trajectory_soundness_score=5,
        justification="Perfect verdict and reasoning alignment",
        is_fallback=False,
    )
    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(return_value=mock_rubric)

    managed_result = {"status": managed_status, "total_items": 1}
    if managed_status == "FAILED":
        managed_result["error"] = "Vertex AI EvalTask exploded"

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value=managed_result),
    ):
        exit_code, summary, _ = await run_evaluation_pipeline(
            scenarios=scenarios,
            threshold=3.5,
            history_path=tmp_path / "history.jsonl",
            export_trace=False,
            allow_fallback=True,
        )

    assert exit_code == 1
    assert summary.all_passed is False
    assert summary.failed_scenarios >= 1


@pytest.mark.asyncio
async def test_swarm_scenario_evaluates_provided_events(mock_paid_tier_env, tmp_path: Path):
    """Scenario-supplied benign events must be evaluated instead of manufactured high-risk swarm events."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    scenarios = [
        {
            "scenario_id": "swarm_benign_001",
            "domain": "swarm_detection",
            "ground_truth_verdict": "ALLOW",
            "events": [
                {
                    "agent_id": "solo_agent_01",
                    "action": "read_file",
                    "target": "/var/log/app/report.txt",
                    "risk_score": 0.1,
                    "timestamp": now.isoformat(),
                },
            ],
        }
    ]

    mock_rubric = SwarmDetectionRubric(
        coordination_detection_score=5,
        temporal_precision_score=5,
        shared_infra_identification_score=5,
        fingerprint_quality_score=5,
        justification="Benign single-agent activity evaluated directly",
        is_fallback=False,
    )
    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(return_value=mock_rubric)

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value={"status": "COMPLETED"}),
    ):
        await run_evaluation_pipeline(
            scenarios=scenarios,
            threshold=3.5,
            history_path=tmp_path / "history.jsonl",
            export_trace=False,
        )

    candidate_result = mock_judge.evaluate.call_args.kwargs["candidate_result"]
    assert candidate_result["verdict"] == "ALLOW"
    assert candidate_result["detected"] is False


@pytest.mark.asyncio
async def test_c2_scenario_events_reach_detector(mock_paid_tier_env, tmp_path: Path):
    """Scenario-supplied C2 events must be recorded into the detector instead of manufactured ones."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    scenarios = [
        {
            "scenario_id": "c2_custom_001",
            "domain": "c2_detection",
            "ground_truth_verdict": "ALLOW",
            "agent_id": "c2_eval_agent_01",
            "events": [
                {
                    "agent_id": "c2_eval_agent_01",
                    "action": "http_get",
                    "target": "https://updates.example.com/pkg",
                    "risk_score": 0.2,
                    "timestamp": now.isoformat(),
                },
            ],
        }
    ]

    mock_rubric = C2DetectionRubric(
        endpoint_classification_score=5,
        beaconing_detection_score=5,
        persistence_identification_score=5,
        cross_pillar_correlation_score=5,
        justification="Custom events routed to detector",
        is_fallback=False,
    )
    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(return_value=mock_rubric)

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value={"status": "COMPLETED"}),
        patch("blackwall.enterprise.advanced_threat_detection.c2.C2InfrastructureDetector.record_event", autospec=True) as record_spy,
    ):
        await run_evaluation_pipeline(
            scenarios=scenarios,
            threshold=3.5,
            history_path=tmp_path / "history.jsonl",
            export_trace=False,
        )

    assert record_spy.call_count == 1
    recorded_event = record_spy.call_args.args[1]
    assert recorded_event.agent_id == "c2_eval_agent_01"
    assert recorded_event.action == "http_get"
    assert recorded_event.target == "https://updates.example.com/pkg"
    assert recorded_event.risk_score == 0.2


@pytest.mark.asyncio
async def test_exploit_chain_branch_executes_detector_without_error(mock_paid_tier_env, tmp_path: Path):
    """Exploit-chain scenarios must run the analyzer against scenario events without execution errors."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    scenarios = [
        {
            "scenario_id": "exploit_chain_001",
            "domain": "exploit_chain",
            "ground_truth_verdict": "BLOCK",
            "agent_id": "exploit_agent_01",
            "events": [
                {
                    "agent_id": "exploit_agent_01",
                    "action": "remote_code_execution",
                    "target": "/tmp/payload_eval.bin",
                    "risk_score": 0.9,
                    "timestamp": now.isoformat(),
                },
                {
                    "agent_id": "exploit_agent_01",
                    "action": "privilege_escalation",
                    "target": "/etc/shadow",
                    "risk_score": 0.95,
                    "timestamp": (now + timedelta(seconds=5)).isoformat(),
                },
            ],
        }
    ]

    mock_rubric = ExploitChainRubric(
        chain_completeness_score=5,
        novelty_calibration_score=5,
        mitre_mapping_accuracy_score=5,
        chaining_confidence_score=5,
        justification="Exploit chain analyzed from scenario events",
        is_fallback=False,
    )
    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(return_value=mock_rubric)

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value={"status": "COMPLETED"}),
    ):
        exit_code, summary, _ = await run_evaluation_pipeline(
            scenarios=scenarios,
            threshold=3.5,
            history_path=tmp_path / "history.jsonl",
            export_trace=False,
        )

    candidate_result = mock_judge.evaluate.call_args.kwargs["candidate_result"]
    assert candidate_result["verdict"] == "BLOCK"
    assert candidate_result["detected"] is True
    assert summary.failed_scenarios == 0
    assert exit_code == 0


@pytest.mark.asyncio
async def test_ailm_branch_consumes_permission_grants(mock_paid_tier_env, tmp_path: Path):
    """AILM scenarios must feed permission grants into AILMTracker and escalate on boundary crossings."""
    scenarios = [
        {
            "scenario_id": "ailm_escalation_001",
            "domain": "ailm",
            "ground_truth_verdict": "BLOCK",
            "agent_id": "ailm_agent_01",
            "permission_grants": [
                {"timestamp": 100, "role": "viewer", "boundary": "user_space"},
                {"timestamp": 200, "role": "editor", "boundary": "sandbox"},
                {"timestamp": 300, "role": "admin", "boundary": "host"},
                {"timestamp": 400, "role": "cluster_admin", "boundary": "kernel_space"},
            ],
        }
    ]

    mock_rubric = AILMDetectionRubric(
        boundary_crossing_detection_score=5,
        permission_composition_accuracy_score=5,
        risk_classification_score=5,
        evidence_completeness_score=5,
        justification="AILM permission composition evaluated",
        is_fallback=False,
    )
    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(return_value=mock_rubric)

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value={"status": "COMPLETED"}),
    ):
        exit_code, summary, _ = await run_evaluation_pipeline(
            scenarios=scenarios,
            threshold=3.5,
            history_path=tmp_path / "history.jsonl",
            export_trace=False,
        )

    candidate_result = mock_judge.evaluate.call_args.kwargs["candidate_result"]
    assert candidate_result["verdict"] == "BLOCK"
    assert candidate_result["detected"] is True
    assert candidate_result.get("risk_levels")
    assert summary.failed_scenarios == 0
    assert exit_code == 0


@pytest.mark.asyncio
async def test_unmatched_domain_fails_gate_without_ground_truth_copy(mock_paid_tier_env, tmp_path: Path):
    """Scenarios with unmapped domains must error out and fail the gate, never copy ground truth."""
    scenarios = [
        {
            "scenario_id": "unmapped_001",
            "domain": "unmapped_evaluation_domain",
            "ground_truth_verdict": "BLOCK",
        }
    ]

    mock_rubric = ThreatInterceptionRubric(
        detection_accuracy_score=5,
        false_positive_control_score=5,
        reasoning_quality_score=5,
        trajectory_soundness_score=5,
        justification="Judge should not be able to pass an unevaluated domain",
        is_fallback=False,
    )
    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(return_value=mock_rubric)

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value={"status": "COMPLETED"}),
    ):
        exit_code, summary, _ = await run_evaluation_pipeline(
            scenarios=scenarios,
            threshold=3.5,
            history_path=tmp_path / "history.jsonl",
            export_trace=False,
        )

    candidate_result = mock_judge.evaluate.call_args.kwargs["candidate_result"]
    assert candidate_result["verdict"] == "ERROR"
    assert candidate_result["detected"] is False
    assert candidate_result.get("is_fallback") is True
    assert summary.failed_scenarios == 1
    assert summary.all_passed is False
    assert exit_code == 1


@pytest.mark.asyncio
async def test_quota_scenario_replays_activity_stream_and_enforces(mock_paid_tier_env, tmp_path: Path):
    """Quota scenarios must replay their activity stream through the enforcer instead of one default sample."""
    scenarios = [
        {
            "scenario_id": "quota_burst_001",
            "domain": "quota_enforcement",
            "activity_stream": [
                {"timestamp": 1000, "tokens": 250, "agent_id": "agent_alpha"},
                {"timestamp": 1500, "tokens": 300, "agent_id": "agent_alpha"},
            ],
            "ground_truth_throttled": True,
            "expected_alert_type": "VELOCITY_BURST",
        },
        {
            "scenario_id": "quota_benign_002",
            "domain": "quota_enforcement",
            "activity_stream": [
                {"timestamp": 1000, "tokens": 200, "agent_id": "agent_beta"},
                {"timestamp": 2000, "tokens": 299, "agent_id": "agent_beta"},
            ],
            "ground_truth_throttled": False,
            "expected_alert_type": "NONE",
        },
    ]

    mock_rubric = ThreatInterceptionRubric(
        detection_accuracy_score=5,
        false_positive_control_score=5,
        reasoning_quality_score=5,
        trajectory_soundness_score=5,
        justification="Quota enforcement replayed the scenario activity stream",
        is_fallback=False,
    )
    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(return_value=mock_rubric)

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value={"status": "COMPLETED"}),
    ):
        exit_code, summary, _ = await run_evaluation_pipeline(
            scenarios=scenarios,
            threshold=3.5,
            history_path=tmp_path / "history.jsonl",
            export_trace=False,
        )

    assert summary.failed_scenarios == 0
    assert exit_code == 0

    candidates = [call.kwargs["candidate_result"] for call in mock_judge.evaluate.call_args_list]
    burst, benign = candidates[0], candidates[1]

    assert burst["verdict"] == "QUARANTINE"
    assert burst["detected"] is True
    assert burst["quarantined"] is True
    assert burst["token_burn_rate_per_sec"] > 500.0

    assert benign["verdict"] == "ALLOW"
    assert benign["detected"] is False
    assert benign["quarantined"] is False
    assert benign["token_burn_rate_per_sec"] <= 500.0


@pytest.mark.asyncio
async def test_managed_dataset_supplies_autorater_columns(mock_paid_tier_env, tmp_path: Path):
    """The managed EvalTask dataset must provide prompt/context/response columns for the autorater."""
    scenarios = [
        {
            "scenario_id": "threat_001",
            "domain": "threat_interception",
            "ground_truth_verdict": "BLOCK",
            "tool_call": {"tool_name": "bash_exec", "arguments": {"cmd": "cat /etc/shadow"}},
        },
        {
            "scenario_id": "quota_001",
            "domain": "quota_enforcement",
            "activity_stream": [{"timestamp": 1000, "tokens": 250, "agent_id": "agent_alpha"}],
            "ground_truth_throttled": True,
        },
    ]

    mock_rubric = ThreatInterceptionRubric(
        detection_accuracy_score=5,
        false_positive_control_score=5,
        reasoning_quality_score=5,
        trajectory_soundness_score=5,
        justification="Managed dataset column verification",
        is_fallback=False,
    )
    mock_judge = MagicMock()
    mock_judge.evaluate = AsyncMock(return_value=mock_rubric)

    with (
        patch("scripts.run_gcp_eval.get_judge_for_domain", return_value=mock_judge),
        patch("blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval.GCPVertexAIEvaluationHarness.run_eval_task", return_value={"status": "COMPLETED"}) as eval_task_spy,
    ):
        exit_code, _, _ = await run_evaluation_pipeline(
            scenarios=scenarios,
            threshold=3.5,
            history_path=tmp_path / "history.jsonl",
            export_trace=False,
        )

    assert exit_code == 0
    dataset = eval_task_spy.call_args.kwargs["dataset"]
    assert len(dataset) == 2
    for record in dataset:
        assert set(record.keys()) == {"prompt", "context", "response"}
        assert isinstance(record["prompt"], str) and record["prompt"]
        assert isinstance(record["context"], str) and record["context"]
        assert isinstance(record["response"], str) and record["response"]


def test_sla_components_match_evaluated_operations():
    """Every pipeline SLA mapping must resolve to an explicit threshold for the operation actually timed."""
    from blackwall.eval.sla_validator import DEFAULT_SLA_THRESHOLDS_MS, SLAValidator
    from scripts.run_gcp_eval import DOMAIN_TO_SLA_COMPONENT

    validator = SLAValidator()
    for domain, component in DOMAIN_TO_SLA_COMPONENT.items():
        resolved = validator.resolve_component_name(component)
        assert resolved in DEFAULT_SLA_THRESHOLDS_MS, f"{domain} maps to undefined component {component}"

    detector_domains = (
        "swarm_detection",
        "c2_detection",
        "exploit_chain",
        "ailm",
        "quota_enforcement",
        "prompt_injection",
    )
    foreign_operations = {"tsg_signature_match", "active_reaction", "structural_gating", "mesh_broadcast"}
    for domain in detector_domains:
        assert DOMAIN_TO_SLA_COMPONENT[domain] not in foreign_operations, (
            f"{domain} is timed against a threshold belonging to a different operation"
        )

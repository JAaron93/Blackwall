"""
Task C.1: AI-Induced Lateral Movement (AILM) Evaluation Scenario.
Requirements: 5.1, 5.2, 5.3, 5.4, 16.1-16.5, 17.1-17.4, 18.1.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from blackwall.enterprise.advanced_threat_detection.ailm import AILMTracker
from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_ailm_eval_samples,
)
from blackwall.enterprise.advanced_threat_detection.models import PermissionGrant
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.eval.judges import AILMDetectionJudge, get_judge_for_domain
from blackwall.eval.rubrics import AILMDetectionRubric
from blackwall.eval.scenarios import AILMScenario


@pytest.mark.gcp_eval
@pytest.mark.asyncio
async def test_ailm_cross_boundary_critical_risk_scenario() -> None:
    """Simulate 3+ cross-boundary permission accumulation and evaluate with AILM judge."""
    eval_store = AttackGraphStore(in_memory=True)
    tracker = AILMTracker(store=eval_store)
    now = datetime.now(UTC)
    start_win = now - timedelta(minutes=10)
    end_win = now + timedelta(minutes=1)

    agent_uuid = uuid4()
    agent_id_str = str(agent_uuid)
    admin_uuid = uuid4()

    # Ingest 4 consecutive grants across trust boundaries:
    # 1. user_space -> 2. sandbox -> 3. host -> 4. kernel_space (3 boundary transitions)
    grants_data = [
        ("read_local_config", "user_space", now - timedelta(minutes=8)),
        ("execute_sandbox_code", "sandbox", now - timedelta(minutes=6)),
        ("host_file_access", "host", now - timedelta(minutes=4)),
        ("kernel_exec", "kernel_space", now - timedelta(minutes=2)),
    ]

    for perm, scope, ts in grants_data:
        grant = PermissionGrant(
            grant_id=uuid4(),
            permission=perm,
            granted_by=admin_uuid,
            granted_to=agent_uuid,
            timestamp=ts,
            scope=scope,
        )
        await tracker.track_permission_grant(grant)

    # Detect permission composition and boundary crossings
    evidence_list = await tracker.detect_permission_composition(
        agent_id=agent_id_str,
        time_window=(start_win, end_win),
    )

    assert len(evidence_list) == 1
    evidence = evidence_list[0]
    assert len(evidence.boundary_crossings) >= 3
    assert evidence.risk_level == "CRITICAL"

    scenario_data = {
        "scenario_id": "ailm_critical_001",
        "domain": "ailm",
        "permission_grants": [
            {"permission": p, "scope": s, "timestamp": t.isoformat()}
            for p, s, t in grants_data
        ],
        "ground_truth_crossings": [
            {"source": "user_space", "target": "sandbox"},
            {"source": "sandbox", "target": "host"},
            {"source": "host", "target": "kernel_space"},
        ],
        "expected_risk_level": "CRITICAL",
    }

    candidate_result = {
        "boundary_crossings": evidence.boundary_crossings,
        "composed_permissions": list(evidence.composed_permissions),
        "risk_level": evidence.risk_level,
    }

    judge = get_judge_for_domain("ailm", enforce_tier=False)
    assert isinstance(judge, AILMDetectionJudge)

    rubric = await judge.evaluate(scenario_data, candidate_result)
    assert isinstance(rubric, AILMDetectionRubric)
    assert rubric.boundary_crossing_detection_score >= 3
    assert rubric.permission_composition_accuracy_score >= 3
    assert rubric.risk_classification_score >= 3
    assert rubric.evidence_completeness_score >= 3
    assert len(rubric.justification) >= 10


@pytest.mark.gcp_eval
@pytest.mark.asyncio
async def test_ailm_eval_dataset_batch_scenarios() -> None:
    """Execute all curated AILM benchmark scenarios through AILMTracker and judge evaluation."""
    samples = get_ailm_eval_samples()
    assert len(samples) >= 10

    judge = get_judge_for_domain("ailm", enforce_tier=False)

    for raw_scenario in samples:
        scenario = AILMScenario.model_validate(raw_scenario)
        tracker = AILMTracker(store=AttackGraphStore(in_memory=True))

        agent_uuid = uuid4()
        agent_id_str = str(agent_uuid)
        admin_uuid = uuid4()
        now = datetime.now(UTC)

        for i, grant_dict in enumerate(scenario.permission_grants):
            scope = grant_dict.get("scope") or grant_dict.get("boundary", "user_space")
            perm = grant_dict.get("permission") or grant_dict.get("role", "exec")
            grant = PermissionGrant(
                grant_id=uuid4(),
                permission=perm,
                granted_by=admin_uuid,
                granted_to=agent_uuid,
                timestamp=now - timedelta(minutes=len(scenario.permission_grants) - i),
                scope=scope,
            )
            await tracker.track_permission_grant(grant)

        evidence_list = await tracker.detect_permission_composition(
            agent_id=agent_id_str,
            time_window=(now - timedelta(hours=1), now + timedelta(minutes=5)),
        )

        if evidence_list:
            cand = {
                "boundary_crossings": evidence_list[0].boundary_crossings,
                "composed_permissions": list(evidence_list[0].composed_permissions),
                "risk_level": evidence_list[0].risk_level,
            }
        else:
            cand = {
                "boundary_crossings": [],
                "composed_permissions": [],
                "risk_level": "LOW",
            }

        rubric = await judge.evaluate(scenario.model_dump(), cand)
        assert isinstance(rubric, AILMDetectionRubric)
        assert rubric.boundary_crossing_detection_score >= 3
        assert rubric.permission_composition_accuracy_score >= 3
        assert rubric.risk_classification_score >= 3
        assert rubric.evidence_completeness_score >= 3

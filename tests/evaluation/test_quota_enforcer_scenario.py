"""
Task C.4: Agent Quota Enforcer and Denial-of-Wallet Evaluation Scenario.
Requirements: 8.1, 8.2, 8.3, 8.4, 16.1-16.5, 17.1-17.4, 18.1.
"""

from unittest.mock import AsyncMock

import pytest

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_quota_enforcement_eval_samples,
)
from blackwall.enterprise.advanced_threat_detection.quota_enforcer import (
    AgentQuotaEnforcer,
)
from blackwall.eval.judges import QuotaEnforcementJudge, get_judge_for_domain
from blackwall.eval.rubrics import QuotaEnforcementRubric
from blackwall.eval.scenarios import QuotaEnforcementScenario


@pytest.mark.gcp_eval
@pytest.mark.asyncio
async def test_quota_enforcer_velocity_spike_quarantine_scenario() -> None:
    """Evaluate token velocity surge (>500 tokens/sec) triggering quarantine with QuotaEnforcementJudge."""
    alert_bus = AlertBus()
    alert_bus.publish = AsyncMock()

    enforcer = AgentQuotaEnforcer(
        alert_bus=alert_bus,
        token_burn_rate_limit=500.0,
        quarantine_duration_sec=60.0,
    )
    judge = get_judge_for_domain("quota_enforcement")
    assert isinstance(judge, QuotaEnforcementJudge)

    agent_id = "surging_agent_01"

    # Track 800 tokens in a single second interval
    usage = await enforcer.track_token_consumption(
        agent_id=agent_id,
        tokens_used=800,
        api_calls=5,
    )
    is_throttled = await enforcer.enforce_quota_limits(agent_id=agent_id)

    assert is_throttled is True
    assert enforcer.is_quarantined(agent_id) is True
    assert alert_bus.publish.called

    scenario_data = {
        "scenario_id": "quota_eval_spike_001",
        "domain": "quota_enforcement",
        "activity_stream": [{"agent_id": agent_id, "tokens": 800, "api_calls": 5}],
        "ground_truth_throttled": True,
        "expected_alert_type": "VELOCITY_BURST",
    }
    candidate_result = {
        "throttled": is_throttled,
        "quarantined": True,
        "burn_rate": usage.token_burn_rate_per_sec,
        "alert_emitted": True,
    }

    rubric = await judge.evaluate(scenario_data, candidate_result)
    assert isinstance(rubric, QuotaEnforcementRubric)
    assert rubric.burn_rate_detection_score >= 3
    assert rubric.throttling_precision_score >= 3
    assert rubric.alert_timeliness_score >= 3
    assert rubric.quarantine_accuracy_score >= 3
    assert len(rubric.justification) >= 10


@pytest.mark.gcp_eval
@pytest.mark.asyncio
async def test_quota_enforcer_eval_dataset_batch_scenarios() -> None:
    """Execute all curated quota enforcement scenarios and evaluate decisions with QuotaEnforcementJudge."""
    samples = get_quota_enforcement_eval_samples()
    assert len(samples) >= 10

    judge = get_judge_for_domain("quota_enforcement")

    for raw_scenario in samples:
        scenario = QuotaEnforcementScenario.model_validate(raw_scenario)
        alert_bus = AlertBus()
        alert_bus.publish = AsyncMock()

        enforcer = AgentQuotaEnforcer(
            alert_bus=alert_bus,
            token_burn_rate_limit=500.0,
            quarantine_duration_sec=60.0,
        )

        agent_id = scenario.scenario_id
        is_throttled = False
        last_usage = None

        total_tokens = sum(item.get("tokens", 0) for item in scenario.activity_stream)
        # Check if total burn rate exceeds threshold
        burn_rate = scenario.metadata.get("rate_tokens_per_sec", total_tokens)

        if burn_rate > 500.0:
            # Simulate high-velocity burst consumption
            last_usage = await enforcer.track_token_consumption(
                agent_id=agent_id,
                tokens_used=int(burn_rate),
                api_calls=len(scenario.activity_stream),
            )
            is_throttled = await enforcer.enforce_quota_limits(agent_id=agent_id)
        else:
            # Simulate low-velocity consumption
            last_usage = await enforcer.track_token_consumption(
                agent_id=agent_id,
                tokens_used=int(burn_rate),
                api_calls=len(scenario.activity_stream),
            )
            is_throttled = await enforcer.enforce_quota_limits(agent_id=agent_id)

        assert is_throttled == scenario.ground_truth_throttled

        cand = {
            "throttled": is_throttled,
            "quarantined": enforcer.is_quarantined(agent_id),
            "burn_rate": last_usage.token_burn_rate_per_sec if last_usage else burn_rate,
            "alert_emitted": alert_bus.publish.called,
        }

        rubric = await judge.evaluate(scenario.model_dump(), cand)
        assert isinstance(rubric, QuotaEnforcementRubric)
        assert rubric.burn_rate_detection_score >= 3
        assert rubric.throttling_precision_score >= 3
        assert rubric.quarantine_accuracy_score >= 3

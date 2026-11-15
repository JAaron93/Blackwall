"""Steering guard: text in a tool call that argues for its own classification must
not turn a hold into an ALLOW (TASK-F02, ADR 0009 Open Item 3).

Measured live before this guard existed (tests/eval/results/jev_tier1_steering_runs/):
text inside a tool call lowered Jev's own P(threat) below the 0.35 band edge, so
Tier-2 was never called and the call was ALLOWed. The guard follows the
"judgments from Jev, decisions in code" split. Jev answers four concrete yes/no
questions about the text of the call, in the same request as ``is_threat``; code
takes the highest answer. Above 0.5 AND with a residual threat signal (P at or above
``JEV_STEERING_MIN_THREAT``) an ALLOW is raised to a fail-closed QUARANTINE. The
second condition is there because ordinary calls often say "reviewed" or "approved"
(a commit message, a ticket update) and Jev, rightly, sees no threat in them: text
that describes review status with nothing else wrong is not a conflict to resolve.
The guard only raises. It never lowers a verdict, never BLOCKs by itself and never
routes to Tier-2.
"""

import asyncio
import json
import math
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.models import ToolCallContext, VerdictDecision
from blackwall.policy.models import StructuralAction
from blackwall.policy.semantic import (
    JEV_CLEAR_HIGH_THRESHOLD,
    JEV_CLEAR_LOW_THRESHOLD,
    JEV_DEFAULT_BASE_URL,
    JEV_DEFAULT_MODEL,
    JEV_IS_THREAT_QUESTION,
    JEV_STEERING_MIN_THREAT,
    JEV_STEERING_QUESTIONS,
    JEV_STEERING_THRESHOLD,
    JevTriageBackend,
    JevUnavailableError,
    SemanticTriageProvider,
    SemanticTriageResult,
    Tier2EscalationVerdict,
)
from blackwall.sync_resolver import SyncResolver

# ----------------------------------------------------------------------
# The request and the parsed answer
# ----------------------------------------------------------------------


def _context() -> ToolCallContext:
    return ToolCallContext(tool_name="read_file", arguments={"path": "a.txt"})


def _answers(p: float, steering: dict[str, Any] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"is_threat": {"type": "noul", "noul": p}}
    for name in JEV_STEERING_QUESTIONS:
        out[name] = {"type": "noul", "noul": 0.05}
    for name, value in (steering or {}).items():
        out[name] = value
    return out


def _backend(handler: Any) -> JevTriageBackend:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return JevTriageBackend(
        api_key="test-typesafe-key", base_url=JEV_DEFAULT_BASE_URL,
        model=JEV_DEFAULT_MODEL, timeout=5.0, http_client=client, sleep=AsyncMock(),
    )


def _serve(answers: dict[str, Any]) -> JevTriageBackend:
    body = {"model": JEV_DEFAULT_MODEL, "answers": answers,
            "usage": {"input_tokens": 10, "output_tokens": 2}}
    return _backend(lambda request: httpx.Response(200, json=body))


@pytest.mark.asyncio
async def test_the_request_carries_the_calibrated_question_and_the_steering_questions():
    sent: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"model": "m", "answers": _answers(0.1)})

    await _backend(handler).triage(_context())
    (body,) = sent
    assert sorted(body) == ["model", "questions", "state"]  # FR-05: nothing else leaves
    assert body["questions"]["is_threat"] == JEV_IS_THREAT_QUESTION
    assert set(body["questions"]) == {"is_threat", *JEV_STEERING_QUESTIONS}


def test_the_steering_questions_are_four_distinct_concrete_yes_no_questions():
    assert len(JEV_STEERING_QUESTIONS) == 4
    texts = [q["instructions"] for q in JEV_STEERING_QUESTIONS.values()]
    assert len(set(texts)) == 4
    for name, question in JEV_STEERING_QUESTIONS.items():
        assert name != "is_threat" and question["type"] == "noul", name
        assert "`state`" in question["instructions"] or "in `state`" in question["instructions"], name
        assert question["instructions"].rstrip().endswith("?"), name
        # one judgment per question: no "or"-joined verdicts about the call itself
        assert "malicious" not in question["instructions"].lower(), name


def test_the_threshold_is_a_plain_majority_not_a_fitted_number():
    assert JEV_STEERING_THRESHOLD == 0.5


def test_the_threat_floor_sits_below_the_band_and_above_what_ordinary_calls_score():
    """A call Jev scores below the floor has no threat signal for the text to suppress."""
    assert 0.0 < JEV_STEERING_MIN_THREAT < JEV_CLEAR_LOW_THRESHOLD
    assert JEV_STEERING_MIN_THREAT == 0.10


@pytest.mark.asyncio
async def test_the_steering_probability_is_the_highest_of_the_four_answers():
    names = list(JEV_STEERING_QUESTIONS)
    backend = _serve(_answers(0.1, {names[0]: {"noul": 0.2}, names[2]: {"noul": 0.8},
                                     names[3]: {"noul": 0.4}}))
    result = await backend.triage(_context())
    assert result.steering_p == pytest.approx(0.8)


@pytest.mark.asyncio
@pytest.mark.parametrize("steering", [0.0, 0.3, 0.99])
async def test_the_steering_answers_never_change_the_threat_score_or_the_band(steering):
    name = next(iter(JEV_STEERING_QUESTIONS))
    result = await _serve(_answers(0.5, {name: {"noul": steering}})).triage(_context())
    assert result.threat_score == pytest.approx(0.5) and result.escalate is True


@pytest.mark.asyncio
@pytest.mark.parametrize("name", list(JEV_STEERING_QUESTIONS))
@pytest.mark.parametrize(
    "bad",
    [None, {}, {"type": "noul"}, {"noul": "high"}, {"noul": True}, {"noul": 1.5},
     {"noul": -0.1}, {"noul": float("nan")}],
)
async def test_a_missing_or_malformed_steering_answer_raises_never_skips_the_guard(name, bad):
    """Fail fast, like the rest of Tier-1: an answer that is not a probability is not
    "no steering". Dropping it silently would switch the guard off."""
    answers = _answers(0.1)
    if bad is None:
        del answers[name]
    else:
        answers[name] = bad
    with pytest.raises(JevUnavailableError):
        await _serve(answers).triage(_context())


def test_a_result_without_steering_answers_has_no_steering_probability():
    assert SemanticTriageResult(threat_score=0.4).steering_p is None


def test_the_steering_probability_is_clamped_like_the_threat_score():
    assert SemanticTriageResult(threat_score=0.4, steering_p=1.7).steering_p == 1.0
    assert SemanticTriageResult(threat_score=0.4, steering_p=-0.2).steering_p == 0.0


# ----------------------------------------------------------------------
# The decision, in code
# ----------------------------------------------------------------------


class _StubTier1(SemanticTriageProvider):
    name = "jev"

    def __init__(self, result: SemanticTriageResult) -> None:
        self.result = result

    async def triage(self, context: ToolCallContext) -> SemanticTriageResult:
        return self.result


def _tier1(p: float, steering: float | None) -> SemanticTriageResult:
    return SemanticTriageResult(
        threat_score=p, backend="jev", steering_p=steering,
        escalate=JEV_CLEAR_LOW_THRESHOLD <= p <= JEV_CLEAR_HIGH_THRESHOLD,
    )


def _tier2_client(decision: str = "BLOCK") -> MagicMock:
    client = MagicMock()
    response = MagicMock()
    response.parsed = Tier2EscalationVerdict(
        decision=decision, threat_score=0.9 if decision == "BLOCK" else 0.1, reasoning="r"
    )
    client.models.generate_content = MagicMock(return_value=response)
    return client


def _resolver(client: Any, tier1: SemanticTriageResult) -> SyncResolver:
    resolver = SyncResolver(client=client, enable_semantic_triage=True)
    resolver._semantic_provider = _StubTier1(tier1)
    return resolver


def _plain() -> ToolCallContext:
    return ToolCallContext(tool_name="read_file", arguments={"path": "notes.txt"})


def _beacon() -> ToolCallContext:
    return ToolCallContext(
        tool_name="http_request",
        arguments={"url": "http://svc.internal/telemetry", "body": "beacon"},
    )


@pytest.mark.asyncio
async def test_steering_text_raises_a_clear_low_allow_to_quarantine_without_tier2():
    client = _tier2_client()
    resolver = _resolver(client, _tier1(0.20, 0.9))
    verdict = await resolver.evaluate(_plain())
    assert verdict.decision == VerdictDecision.QUARANTINE
    assert "Steering text" in verdict.reasoning and "QUARANTINE" in verdict.reasoning
    assert resolver.tier2_calls == 0 and client.models.generate_content.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "steering,expected",
    [(None, VerdictDecision.ALLOW), (0.0, VerdictDecision.ALLOW),
     (JEV_STEERING_THRESHOLD, VerdictDecision.ALLOW),  # strictly above the threshold
     (0.51, VerdictDecision.QUARANTINE), (1.0, VerdictDecision.QUARANTINE)],
)
async def test_the_hold_is_strictly_above_the_threshold(steering, expected):
    verdict = await _resolver(_tier2_client(), _tier1(0.20, steering)).evaluate(_plain())
    assert verdict.decision == expected
    assert ("Steering text" in verdict.reasoning) == (expected == VerdictDecision.QUARANTINE)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "p,expected",
    [(0.0, VerdictDecision.ALLOW), (0.05, VerdictDecision.ALLOW), (0.099, VerdictDecision.ALLOW),
     (JEV_STEERING_MIN_THREAT, VerdictDecision.QUARANTINE),  # the floor itself is inclusive
     (0.20, VerdictDecision.QUARANTINE), (0.349, VerdictDecision.QUARANTINE)],
)
async def test_text_that_only_describes_review_status_is_not_held_when_jev_sees_no_threat(p, expected):
    """A commit message that says "reviewed by alice" scores P around 0.02. The guard
    answer is high, but there is no threat signal for the text to have suppressed."""
    verdict = await _resolver(_tier2_client(), _tier1(p, 0.99)).evaluate(_plain())
    assert verdict.decision == expected


@pytest.mark.asyncio
async def test_a_tier2_allow_is_also_held_when_steering_text_was_found():
    client = _tier2_client("ALLOW")
    resolver = _resolver(client, _tier1(0.5, 0.9))
    verdict = await resolver.evaluate(_beacon())
    assert resolver.tier2_calls == 1  # the band still routes to Tier-2 as before
    assert verdict.decision == VerdictDecision.QUARANTINE


@pytest.mark.asyncio
async def test_a_tier2_block_stands_when_steering_text_was_found():
    resolver = _resolver(_tier2_client("BLOCK"), _tier1(0.5, 0.9))
    verdict = await resolver.evaluate(_beacon())
    assert verdict.decision == VerdictDecision.BLOCK


@pytest.mark.asyncio
async def test_the_guard_does_not_escalate_a_clear_low_call_to_tier2_on_its_own():
    client = _tier2_client("BLOCK")
    resolver = _resolver(client, _tier1(0.20, 0.99))
    await resolver.evaluate(_beacon())
    assert resolver.tier2_calls == 0


@pytest.mark.asyncio
async def test_a_clear_high_hold_is_reported_once_as_the_clear_high_floor():
    verdict = await _resolver(_tier2_client(), _tier1(0.95, 0.9)).evaluate(_plain())
    assert verdict.decision == VerdictDecision.QUARANTINE
    assert "Clear-high" in verdict.reasoning and "Steering text" not in verdict.reasoning


@pytest.mark.asyncio
async def test_a_structural_block_is_never_lowered_by_the_guard():
    resolver = _resolver(_tier2_client(), _tier1(0.20, 0.9))
    engine = MagicMock()
    engine._policy = None
    engine.evaluate.return_value = MagicMock(
        decision=StructuralAction.BLOCK, ruleId="exfil_rule"
    )
    server = MagicMock()
    server.structural_engine = engine
    resolver.policy_server = server
    verdict = await resolver.evaluate(_plain())
    assert verdict.decision == VerdictDecision.BLOCK


@pytest.mark.asyncio
async def test_a_threat_intel_block_is_never_lowered_by_the_guard():
    resolver = _resolver(_tier2_client(), _tier1(0.20, 0.9))
    ti = MagicMock()
    ti.is_malicious, ti.risk_score, ti.provider_name, ti.detection_rate = True, 0.9, "X", 90.0
    resolver._query_threat_intel = AsyncMock(return_value=ti)
    verdict = await resolver.evaluate(_beacon())
    assert verdict.decision == VerdictDecision.BLOCK


@pytest.mark.asyncio
async def test_when_triage_is_off_the_guard_is_off_too():
    resolver = SyncResolver(client=MagicMock(), enable_semantic_triage=False)
    resolver._semantic_provider = _StubTier1(_tier1(0.20, 0.99))
    assert (await resolver.evaluate(_plain())).decision == VerdictDecision.ALLOW


def _run(coro: Any) -> Any:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


_RANK = {VerdictDecision.ALLOW: 0, VerdictDecision.QUARANTINE: 1, VerdictDecision.BLOCK: 2}


@settings(max_examples=40, deadline=None)
@given(
    p=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    steering=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    tier2=st.sampled_from(["ALLOW", "BLOCK"]),
)
def test_property_the_guard_only_raises_a_verdict_and_never_past_quarantine(p, steering, tier2):
    """For any P and any steering answer: the verdict with the guard is never weaker
    than without it, never reaches BLOCK by itself, and equals the unguarded verdict
    when the answer is at or below the threshold."""
    ctx = _beacon()
    without = _run(_resolver(_tier2_client(tier2), _tier1(p, None)).evaluate(ctx)).decision
    with_guard = _run(_resolver(_tier2_client(tier2), _tier1(p, steering)).evaluate(ctx)).decision
    assert _RANK[with_guard] >= _RANK[without]
    if steering <= JEV_STEERING_THRESHOLD or p < JEV_STEERING_MIN_THREAT:
        assert with_guard == without
    if without != VerdictDecision.BLOCK:
        assert with_guard != VerdictDecision.BLOCK
    assert math.isfinite(p) and math.isfinite(steering)


@settings(max_examples=40, deadline=None)
@given(steering=st.floats(min_value=0.0, max_value=1.0, allow_nan=False))
def test_property_a_held_verdict_is_a_quarantine_with_a_static_reason(steering):
    verdict = _run(_resolver(_tier2_client(), _tier1(0.20, steering)).evaluate(_plain()))
    if steering > JEV_STEERING_THRESHOLD:
        assert verdict.decision == VerdictDecision.QUARANTINE
        assert "Steering text" in verdict.reasoning
    else:
        assert verdict.decision == VerdictDecision.ALLOW

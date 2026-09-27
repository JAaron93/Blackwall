"""BDD acceptance suite for the Tier-1 Jev pipeline (TASK-D01, NFR-04).

Governing spec: .kiro/specs/tier-1-jev-addition/
All scenarios are mocked — no live Gateway or Gemini calls (NFR-03).
"""

import json
import logging
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.models import ToolCallContext, VerdictDecision
from blackwall.policy.semantic import (
    GeminiTriageBackend,
    JevTriageBackend,
    SemanticTriageProvider,
    SemanticTriageResult,
)
from blackwall.sync_resolver import SyncResolver
from tests.step_defs.async_utils import run_async

from tests.unit.test_tier2_escalation import (  # reuse shared doubles
    _beacon_context,
    _benign_context,
    _high_risk_context,
    _StubTier1,
)

scenarios("../features/jev_tier1_triage.feature")


class BDDState:
    def __init__(self) -> None:
        self.resolver: SyncResolver | None = None
        self.tier1: _StubTier1 | None = None
        self.gemini_client: MagicMock | None = None
        self.tier2_decision: str = "BLOCK"
        self.tier2_score: float = 0.9
        self.repo: MagicMock | None = None
        self.aba: AsyncMock | None = None
        self.captured_requests: list[httpx.Request] = []
        self.jev_backend: JevTriageBackend | None = None
        self.verdict = None
        self.triage_result = None
        self.sleeps: list[float] = []
        self.context: ToolCallContext | None = None


@pytest.fixture
def state() -> BDDState:
    return BDDState()


def _tier1(p: float) -> SemanticTriageResult:
    return SemanticTriageResult(
        threat_score=p,
        confidence=0.9,
        backend="jev",
        escalate=0.35 <= p <= 0.75,
    )


def _configure_tier2(state: BDDState) -> None:
    response = MagicMock()
    response.parsed = None
    response.text = json.dumps(
        {
            "decision": state.tier2_decision,
            "threat_score": state.tier2_score,
            "reasoning": "deep contextual reasoning verdict",
        }
    )
    state.gemini_client = MagicMock()
    state.gemini_client.models.generate_content = MagicMock(return_value=response)


# ----------------------------------------------------------------------
# Given steps
# ----------------------------------------------------------------------


@given(parsers.parse('a SyncResolver with a stubbed Jev backend returning P "{p}"'))
def resolver_with_stub_jev(state: BDDState, p: str) -> None:
    state.tier1 = _StubTier1(_tier1(float(p)))
    state.gemini_client = MagicMock()
    state.resolver = SyncResolver(
        client=state.gemini_client, enable_semantic_triage=True
    )
    state.resolver._semantic_provider = state.tier1
    state.resolver.aba = AsyncMock()  # keep signature writes hermetic


@given(
    parsers.parse(
        'a SyncResolver with a stubbed Jev backend returning P "{p}" '
        "and a malicious threat-intel response"
    )
)
def resolver_with_stub_jev_and_malicious_ti(state: BDDState, p: str) -> None:
    resolver_with_stub_jev(state, p)
    ti_resp = MagicMock()
    ti_resp.is_malicious = True
    ti_resp.risk_score = 0.9
    ti_resp.provider_name = "AlienVaultOTX"
    ti_resp.detection_rate = 90.0
    state.resolver._query_threat_intel = AsyncMock(return_value=ti_resp)


@given(
    parsers.parse(
        "a SyncResolver with repository and behavioral-analytics mocks "
        'and a stubbed Jev backend returning P "{p}"'
    )
)
def resolver_with_repo_and_stub_jev(state: BDDState, p: str) -> None:
    resolver_with_stub_jev(state, p)
    state.repo = MagicMock()
    state.repo.find_matching_signature = AsyncMock(return_value=None)
    state.repo.writeSignature = AsyncMock()
    state.aba = AsyncMock()
    state.resolver.repo = state.repo
    state.resolver.aba = state.aba


@given("a real Jev backend bound to a capturing gateway")
def resolver_with_capturing_jev_backend(state: BDDState) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        state.captured_requests.append(request)
        return httpx.Response(
            200,
            json={
                "model": "typesafe-ai/jev",
                "answers": {"is_threat": {"type": "boolean", "probability": 0.02}},
                "usage": {"inputTokens": 100, "outputTokens": 5},
                "providerMetadata": {"gateway": {"cost": "0.00001"}},
            },
        )

    state.jev_backend = JevTriageBackend(
        api_key="test-gateway-key",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    state.gemini_client = MagicMock()
    state.resolver = SyncResolver(
        client=state.gemini_client, enable_semantic_triage=True
    )
    state.resolver._semantic_provider = state.jev_backend


@given(
    parsers.parse(
        "a real Jev backend rate-limited on every call with a Gemini fallback "
        'returning P "{p}"'
    )
)
def resolver_with_rate_limited_jev_backend(
    state: BDDState, p: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="blackwall.policy.semantic")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "rate limit"})

    async def fake_sleep(seconds: float) -> None:
        state.sleeps.append(seconds)

    gemini_client = MagicMock()
    fallback_response = MagicMock()
    fallback_response.parsed = MagicMock(threat_score=float(p))
    gemini_client.models.generate_content = MagicMock(return_value=fallback_response)

    state.jev_backend = JevTriageBackend(
        api_key="test-gateway-key",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        fallback=GeminiTriageBackend(gemini_client),
        sleep=fake_sleep,
    )
    state.gemini_client = MagicMock()
    state.resolver = SyncResolver(
        client=state.gemini_client, enable_semantic_triage=True
    )
    state.resolver._semantic_provider = state.jev_backend


@given(parsers.parse('Tier-2 returns "{decision}" with threat_score "{score}"'))
def configure_tier2_verdict(state: BDDState, decision: str, score: str) -> None:
    state.tier2_decision = decision
    state.tier2_score = float(score)
    _configure_tier2(state)
    state.resolver.client = state.gemini_client
    state.resolver._tier2_backend = None  # rebuild from the configured client


# ----------------------------------------------------------------------
# When steps
# ----------------------------------------------------------------------


@when("a benign tool call is evaluated")
def evaluate_benign(state: BDDState) -> None:
    state.context = _benign_context()
    state.verdict = run_async(state.resolver.evaluate(state.context))


@when("a high-risk tool call is evaluated")
def evaluate_high_risk(state: BDDState) -> None:
    state.context = _high_risk_context()
    state.verdict = run_async(state.resolver.evaluate(state.context))


@when("a C2-beacon-like tool call is evaluated")
def evaluate_beacon(state: BDDState) -> None:
    state.context = _beacon_context()

    async def _flow() -> None:
        state.verdict = await state.resolver.evaluate(state.context)
        # Same-loop flush so scheduled signature/attribution tasks run.
        await state.resolver.flush_background_tasks()

    run_async(_flow())


@when(
    parsers.parse(
        'a tool call containing the secret "AWS_SECRET_ACCESS_KEY=rawsecretvalue" is triaged'
    )
)
def evaluate_secret(state: BDDState) -> None:
    state.context = ToolCallContext(
        tool_name="run_command",
        arguments={"cmd": "AWS_SECRET_ACCESS_KEY=rawsecretvalue aws s3 ls"},
    )
    state.verdict = run_async(state.resolver.evaluate(state.context))


@when("a high-risk tool call is triaged through the failing gateway")
def evaluate_through_failing_gateway(state: BDDState) -> None:
    state.context = _high_risk_context()
    state.verdict = run_async(state.resolver.evaluate(state.context))


# ----------------------------------------------------------------------
# Then steps
# ----------------------------------------------------------------------


@then(parsers.parse('the verdict decision is "{decision}"'))
def assert_decision(state: BDDState, decision: str) -> None:
    assert state.verdict is not None
    assert state.verdict.decision == VerdictDecision[decision]


@then("Tier-2 escalation is never invoked")
def assert_no_tier2(state: BDDState) -> None:
    # The Gemini client may still serve attribution/reporting; Tier-2
    # invocation is tracked by the resolver's own escalation counter.
    assert state.resolver.tier2_calls == 0


@then(parsers.parse('Tier-2 escalation was invoked exactly "{n}" times'))
def assert_tier2_calls(state: BDDState, n: str) -> None:
    assert state.resolver.tier2_calls == int(n)


@then("the verdict reasoning records Tier-2 provenance")
def assert_tier2_provenance(state: BDDState) -> None:
    assert "Tier-2 escalation" in state.verdict.reasoning


@then("a threat signature is written to the graph with the blocked verdict")
def assert_signature_written(state: BDDState) -> None:
    run_async(state.resolver.flush_background_tasks())
    assert state.resolver._inline_signatures_generated == 1
    state.aba.generateSignature.assert_awaited_once()
    event = state.aba.generateSignature.await_args.args[0]
    assert event.verdict.decision == VerdictDecision.BLOCK


@then(parsers.parse('the outbound state contains "{fragment}"'))
def assert_state_contains(state: BDDState, fragment: str) -> None:
    assert state.captured_requests, "no Gateway egress captured"
    body = json.loads(state.captured_requests[0].content.decode())
    assert fragment in body["state"]


@then(parsers.parse('the outbound state does not contain "{fragment}"'))
def assert_state_excludes(state: BDDState, fragment: str) -> None:
    body = json.loads(state.captured_requests[0].content.decode())
    assert fragment not in body["state"]


@then("the outbound request disallows prompt training")
def assert_no_training(state: BDDState) -> None:
    body = json.loads(state.captured_requests[0].content.decode())
    assert body["providerOptions"]["gateway"]["disallowPromptTraining"] is True


@then(parsers.parse('the triage signal backend is "{backend}"'))
def assert_signal_backend(
    state: BDDState, backend: str, caplog: pytest.LogCaptureFixture
) -> None:
    if state.triage_result is not None:
        assert state.triage_result.backend == backend
        return
    records = [r for r in caplog.records if r.message == "jev_triage"]
    assert records, "expected a jev_triage record"
    assert records[-1].backend == backend


@then("the jev_triage record marks the signal as fallback")
def assert_fallback_record(state: BDDState, caplog: pytest.LogCaptureFixture) -> None:
    records = [
        r
        for r in caplog.records
        if r.message == "jev_triage" and getattr(r, "is_fallback", False)
    ]
    assert records, "expected an is_fallback jev_triage record"
    assert records[0].backend == "gemini"
    assert records[0].p == pytest.approx(0.95)

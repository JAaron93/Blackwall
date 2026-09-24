"""Unit tests for the Jev Tier-1 triage backend (TASK-B01, FR-02/FR-05/NFR-06).

Governing spec: .kiro/specs/tier-1-jev-addition/

The Gateway is mocked via ``httpx.MockTransport`` — no live calls in unit
tests (NFR-03); live Jev traffic is eval-harness-only.
"""

import json
import logging
from typing import Any, Dict, List, Optional

import httpx
import pytest

from blackwall.models import ToolCallContext
from blackwall.policy.semantic import (
    JEV_API_KEY_ENV_VAR,
    JEV_CLEAR_HIGH_THRESHOLD,
    JEV_CLEAR_LOW_THRESHOLD,
    JEV_DEFAULT_GATEWAY_URL,
    JEV_DEFAULT_MODEL,
    GeminiTriageBackend,
    JevTriageBackend,
    SemanticTriageProvider,
    SemanticTriageResult,
    build_semantic_provider,
)


def _context(
    tool_name: str = "execute_bash",
    arguments: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> ToolCallContext:
    return ToolCallContext(
        tool_name=tool_name,
        arguments=arguments if arguments is not None else {"cmd": "ls -la"},
        metadata=metadata,
    )


def _gateway_payload(
    probability: float,
    *,
    confidence: Any = None,
    input_tokens: int = 120,
    output_tokens: int = 8,
    cost: str = "0.00001155",
) -> Dict[str, Any]:
    provider_metadata: Dict[str, Any] = {"gateway": {"cost": cost}}
    if confidence is not None:
        provider_metadata["typesafe"] = confidence
    return {
        "model": JEV_DEFAULT_MODEL,
        "answers": {
            "is_threat": {"type": "boolean", "probability": probability}
        },
        "usage": {"inputTokens": input_tokens, "outputTokens": output_tokens},
        "providerMetadata": provider_metadata,
    }


def _backend(
    handler: Any,
    requests: List[httpx.Request],
    **kwargs: Any,
) -> JevTriageBackend:
    def _capture(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(_capture))
    # Pin ctor defaults explicitly so ambient JEV_* env vars (e.g. a
    # suite-wide JEV_GATEWAY_URL) cannot leak into these tests.
    kwargs.setdefault("api_key", "test-gateway-key")
    kwargs.setdefault("gateway_url", JEV_DEFAULT_GATEWAY_URL)
    kwargs.setdefault("model", JEV_DEFAULT_MODEL)
    kwargs.setdefault("timeout", 5.0)
    kwargs.setdefault("max_attempts", 3)
    return JevTriageBackend(http_client=client, **kwargs)


# ----------------------------------------------------------------------
# Signal mapping (FR-02): fixed 0.35/0.75 band, boundaries inclusive
# ----------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "probability,escalate",
    [
        (0.02, False),  # clear-low signal (TASK-B01 mock: allow)
        (0.98, False),  # clear-high signal (TASK-B01 mock: block)
        (0.60, True),  # ambiguity band (TASK-B01 mock: escalate)
        # SVM-style boundary probes
        (0.349, False),
        (0.35, True),
        (0.75, True),
        (0.751, False),
    ],
)
async def test_probability_maps_to_signal_with_fixed_band(
    probability: float, escalate: bool
):
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_gateway_payload(probability)),
        requests,
    )
    result = await backend.triage(_context())
    assert result is not None
    assert result.threat_score == pytest.approx(probability)
    assert result.backend == "jev"
    assert result.escalate is escalate
    assert (JEV_CLEAR_LOW_THRESHOLD <= probability <= JEV_CLEAR_HIGH_THRESHOLD) == (
        escalate
    )


async def test_result_confidence_defaults_to_none_when_absent():
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_gateway_payload(0.02)), requests
    )
    result = await backend.triage(_context())
    assert result is not None
    assert result.confidence is None


@pytest.mark.parametrize("confidence", [0.97, {"confidence": 0.97}])
async def test_confidence_extracted_from_typesafe_provider_metadata(confidence: Any):
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(
            200, json=_gateway_payload(0.02, confidence=confidence)
        ),
        requests,
    )
    result = await backend.triage(_context())
    assert result is not None
    assert result.confidence == pytest.approx(0.97)


# ----------------------------------------------------------------------
# Egress contract (FR-05): payload shape, auth, disallowPromptTraining
# ----------------------------------------------------------------------


async def test_request_hits_v1_evaluate_with_bearer_and_no_training_flag():
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_gateway_payload(0.02)), requests
    )
    await backend.triage(_context())
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == JEV_DEFAULT_GATEWAY_URL
    assert request.headers["Authorization"] == "Bearer test-gateway-key"

    body = json.loads(request.content.decode())
    assert body["model"] == JEV_DEFAULT_MODEL
    assert set(body["questions"].keys()) == {"is_threat"}
    assert body["questions"]["is_threat"]["type"] == "boolean"
    assert body["providerOptions"]["gateway"]["disallowPromptTraining"] is True


async def test_state_is_tool_arguments_metadata_lines_verbatim():
    """State mirrors the sanitized Tool/Arguments/Metadata shape — the backend
    consumes the pre-sanitized context as-is and never re-sanitizes."""
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_gateway_payload(0.02)), requests
    )
    context = _context(
        tool_name="read_file",
        arguments={"path": "/var/log/app.log"},
        metadata={"agent": "bot-7"},
    )
    await backend.triage(context)
    body = json.loads(requests[0].content.decode())
    assert body["state"] == (
        "Tool: read_file\n"
        "Arguments: {'path': '/var/log/app.log'}\n"
        "Metadata: {'agent': 'bot-7'}"
    )


async def test_sanitized_placeholders_pass_through_verbatim():
    """FR-05: [[PLACEHOLDER]] redactions must reach the Gateway untouched;
    no raw secret material is ever introduced by the backend."""
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_gateway_payload(0.02)), requests
    )
    context = _context(
        arguments={"token": "[[AWS_SECRET_ACCESS_KEY]]", "host": "wd-bouygues.com"}
    )
    await backend.triage(context)
    state = json.loads(requests[0].content.decode())["state"]
    assert "[[AWS_SECRET_ACCESS_KEY]]" in state
    assert "wd-bouygues.com" in state


# ----------------------------------------------------------------------
# Abstention contract: never fail open, never synthesize a score
# ----------------------------------------------------------------------


async def test_missing_api_key_abstains(monkeypatch):
    monkeypatch.delenv(JEV_API_KEY_ENV_VAR, raising=False)
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_gateway_payload(0.02)),
        requests,
        api_key="",
    )
    assert await backend.triage(_context()) is None
    assert requests == []  # no egress without credentials


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"answers": {}},
        {"answers": {"is_threat": {"type": "boolean"}}},
        {"answers": {"is_threat": {"type": "boolean", "probability": "high"}}},
    ],
)
async def test_malformed_gateway_payload_abstains(payload: Dict[str, Any]):
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=payload), requests
    )
    assert await backend.triage(_context()) is None


async def test_backend_is_a_provider():
    assert issubclass(JevTriageBackend, SemanticTriageProvider)
    assert JevTriageBackend(api_key="k").name == "jev"


def test_env_knobs_configure_backend(monkeypatch):
    monkeypatch.setenv(JEV_API_KEY_ENV_VAR, "env-key")
    monkeypatch.setenv("JEV_GATEWAY_URL", "https://gateway.internal/evaluate")
    monkeypatch.setenv("JEV_MODEL", "typesafe-ai/jev-custom")
    monkeypatch.setenv("JEV_MAX_ATTEMPTS", "7")
    monkeypatch.setenv("JEV_TIMEOUT_S", "2.5")
    backend = JevTriageBackend()
    assert backend.api_key == "env-key"
    assert backend.gateway_url == "https://gateway.internal/evaluate"
    assert backend.model == "typesafe-ai/jev-custom"
    assert backend.max_attempts == 7
    assert backend.timeout == pytest.approx(2.5)


def test_ctor_args_beat_env(monkeypatch):
    monkeypatch.setenv("JEV_MAX_ATTEMPTS", "7")
    backend = JevTriageBackend(api_key="k", max_attempts=2)
    assert backend.max_attempts == 2


# ----------------------------------------------------------------------
# Registry integration (FR-01)
# ----------------------------------------------------------------------


def test_build_semantic_provider_jev_with_key(monkeypatch):
    monkeypatch.setenv(JEV_API_KEY_ENV_VAR, "test-gateway-key")
    client = object()
    provider = build_semantic_provider(client, "jev")
    assert isinstance(provider, JevTriageBackend)
    assert isinstance(provider.fallback, GeminiTriageBackend)
    assert provider.fallback.client is client


def test_build_semantic_provider_jev_without_key_degrades(monkeypatch):
    monkeypatch.delenv(JEV_API_KEY_ENV_VAR, raising=False)
    provider = build_semantic_provider(object(), "jev")
    assert isinstance(provider, GeminiTriageBackend)


# ----------------------------------------------------------------------
# Bounded 429 backoff + fail-closed fallback (TASK-B02, FR-06)
# ----------------------------------------------------------------------


class _StubFallback(SemanticTriageProvider):
    """Gemini-side fallback double for fail-closed routing assertions."""

    name = "gemini"

    def __init__(
        self,
        result: Optional[SemanticTriageResult] = None,
        error: Optional[BaseException] = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls = 0

    async def triage(self, context: ToolCallContext) -> Optional[SemanticTriageResult]:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


class _FakeSleep:
    def __init__(self) -> None:
        self.calls: List[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _rate_limited(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        429, json={"message": "rate limit exceeded", "error_type": "rate_limit"}
    )


async def test_429_storm_exhausts_bounded_attempts_then_falls_back():
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()
    fallback = _StubFallback(
        result=SemanticTriageResult(threat_score=0.9, backend="gemini")
    )
    backend = _backend(_rate_limited, requests, fallback=fallback, sleep=sleep)
    result = await backend.triage(_context())
    assert len(requests) == backend.max_attempts == 3
    assert sleep.calls == [0.5, 1.0]  # min(cap, base * 2**attempt)
    assert fallback.calls == 1
    assert result is not None
    assert result.backend == "gemini"  # signal attributed to its producer
    assert result.threat_score == pytest.approx(0.9)


async def test_429_then_success_retries_once_with_backoff():
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()
    responses = iter(
        [
            httpx.Response(429, json={"message": "slow down"}),
            httpx.Response(200, json=_gateway_payload(0.02)),
        ]
    )
    backend = _backend(lambda request: next(responses), requests, sleep=sleep)
    result = await backend.triage(_context())
    assert len(requests) == 2
    assert sleep.calls == [0.5]
    assert result is not None
    assert result.backend == "jev"
    assert result.threat_score == pytest.approx(0.02)


async def test_backoff_delay_is_capped():
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()
    backend = _backend(
        _rate_limited,
        requests,
        max_attempts=4,
        backoff_base_s=2.0,
        backoff_cap_s=3.0,
        sleep=sleep,
    )
    assert await backend.triage(_context()) is None
    assert sleep.calls == [2.0, 3.0, 3.0]


async def test_timeout_falls_back_immediately_without_retry():
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()

    def _hang(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("gateway stalled", request=request)

    fallback = _StubFallback(
        result=SemanticTriageResult(threat_score=0.4, backend="gemini")
    )
    backend = _backend(_hang, requests, fallback=fallback, sleep=sleep)
    result = await backend.triage(_context())
    assert len(requests) == 1  # transient network errors are not retried
    assert sleep.calls == []
    assert fallback.calls == 1
    assert result is not None and result.backend == "gemini"


async def test_non_429_client_error_falls_back_without_retry():
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()
    fallback = _StubFallback(
        result=SemanticTriageResult(threat_score=0.4, backend="gemini")
    )
    backend = _backend(
        lambda request: httpx.Response(
            400, json={"message": "bad request", "error_type": "invalid_request"}
        ),
        requests,
        fallback=fallback,
        sleep=sleep,
    )
    result = await backend.triage(_context())
    assert len(requests) == 1  # 4xx contract errors must never be retried
    assert sleep.calls == []
    assert fallback.calls == 1
    assert result is not None and result.backend == "gemini"


async def test_fallback_failure_abstains_never_allows():
    requests: List[httpx.Request] = []
    fallback = _StubFallback(error=RuntimeError("gemini down"))
    backend = _backend(
        _rate_limited, requests, fallback=fallback, sleep=_FakeSleep()
    )
    assert await backend.triage(_context()) is None


async def test_429_storm_without_fallback_abstains():
    requests: List[httpx.Request] = []
    backend = _backend(_rate_limited, requests, sleep=_FakeSleep())
    assert await backend.triage(_context()) is None
    assert len(requests) == 3


# ----------------------------------------------------------------------
# Observability (TASK-B03, FR-07): one structured record per triage
# ----------------------------------------------------------------------

SEMANTIC_LOGGER = "blackwall.policy.semantic"


def _triage_records(caplog: Any) -> List[Any]:
    return [r for r in caplog.records if r.message == "jev_triage"]


async def test_success_emits_structured_triage_record(caplog):
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(
            200, json=_gateway_payload(0.02, confidence=0.97)
        ),
        requests,
    )
    with caplog.at_level(logging.INFO, logger=SEMANTIC_LOGGER):
        result = await backend.triage(_context())
    assert result is not None
    records = _triage_records(caplog)
    assert len(records) == 1
    record = records[0]
    assert record.backend == "jev"
    assert record.p == pytest.approx(0.02)
    assert record.confidence == pytest.approx(0.97)
    assert record.latency_ms >= 0.0
    assert record.input_tokens == 120
    assert record.output_tokens == 8
    assert record.gateway_cost == "0.00001155"
    assert record.is_fallback is False


async def test_snake_case_usage_keys_are_tolerated(caplog):
    payload = _gateway_payload(0.98)
    payload["usage"] = {"input_tokens": 200, "output_tokens": 12}
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=payload), requests
    )
    with caplog.at_level(logging.INFO, logger=SEMANTIC_LOGGER):
        await backend.triage(_context())
    record = _triage_records(caplog)[0]
    assert record.input_tokens == 200
    assert record.output_tokens == 12


async def test_fallback_emits_honest_is_fallback_record(caplog):
    requests: List[httpx.Request] = []
    fallback = _StubFallback(
        result=SemanticTriageResult(threat_score=0.9, backend="gemini")
    )
    backend = _backend(
        _rate_limited, requests, fallback=fallback, sleep=_FakeSleep()
    )
    with caplog.at_level(logging.INFO, logger=SEMANTIC_LOGGER):
        result = await backend.triage(_context())
    assert result is not None
    records = _triage_records(caplog)
    assert len(records) == 1
    record = records[0]
    assert record.is_fallback is True
    assert record.backend == "gemini"
    assert record.p == pytest.approx(0.9)
    assert record.latency_ms >= 0.0
    assert record.input_tokens is None
    assert record.output_tokens is None
    assert record.gateway_cost is None


async def test_total_abstention_emits_no_triage_record(caplog):
    requests: List[httpx.Request] = []
    backend = _backend(_rate_limited, requests, sleep=_FakeSleep())
    with caplog.at_level(logging.INFO, logger=SEMANTIC_LOGGER):
        assert await backend.triage(_context()) is None
    assert _triage_records(caplog) == []

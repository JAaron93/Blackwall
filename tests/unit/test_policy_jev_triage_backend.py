"""Unit tests for the Jev Tier-1 triage backend (TASK-B01, FR-02/FR-05/NFR-06).

Governing spec: .kiro/specs/tier-1-jev-addition/ (transport: ADR 0008)

The TypeSafe AI API is mocked via ``httpx.MockTransport`` — no live calls in
unit tests (NFR-03); live Jev traffic is eval-harness-only.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from blackwall.models import ToolCallContext
from blackwall.policy.semantic import (
    JEV_API_KEY_ENV_VAR,
    JEV_BASE_URL_ENV_VAR,
    JEV_CLEAR_HIGH_THRESHOLD,
    JEV_CLEAR_LOW_THRESHOLD,
    JEV_DEFAULT_BASE_URL,
    JEV_DEFAULT_MODEL,
    JEV_IS_THREAT_QUESTION,
    JEV_RETRY_DELAY_S,
    JEV_SYSTEM_ONE_PATH,
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


SYSTEM_ONE_URL = f"{JEV_DEFAULT_BASE_URL}{JEV_SYSTEM_ONE_PATH}"


def _system_one_payload(
    probability: float,
    *,
    input_tokens: int = 120,
    output_tokens: int = 8,
) -> Dict[str, Any]:
    """Success body of ``POST /v1/systemone`` for one ``noul`` question."""
    return {
        "model": JEV_DEFAULT_MODEL,
        "answers": {"is_threat": {"type": "noul", "noul": probability}},
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
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
    # Pin ctor defaults explicitly so ambient JEV_* / TYPESAFE_* env vars (e.g.
    # a developer .env with TYPESAFE_BASE_URL) cannot leak into these tests.
    kwargs.setdefault("api_key", "test-typesafe-key")
    kwargs.setdefault("base_url", JEV_DEFAULT_BASE_URL)
    kwargs.setdefault("model", JEV_DEFAULT_MODEL)
    kwargs.setdefault("timeout", 5.0)
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
        lambda request: httpx.Response(200, json=_system_one_payload(probability)),
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


async def test_noul_answer_has_no_confidence():
    """TypeSafe docs: a noul answer returns no separate confidence — the
    probability already carries the uncertainty. The backend must not invent
    one."""
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_system_one_payload(0.02)), requests
    )
    result = await backend.triage(_context())
    assert result is not None
    assert result.confidence is None


async def test_legacy_gateway_provider_metadata_is_never_parsed():
    """The first-party API has no providerMetadata. A stray Vercel-era
    ``providerMetadata.typesafe`` value must not be promoted to a confidence."""
    payload = _system_one_payload(0.02)
    payload["providerMetadata"] = {"typesafe": 0.97, "gateway": {"cost": "1"}}
    requests: List[httpx.Request] = []
    backend = _backend(lambda request: httpx.Response(200, json=payload), requests)
    result = await backend.triage(_context())
    assert result is not None
    assert result.confidence is None


# ----------------------------------------------------------------------
# Egress contract (FR-05): endpoint, auth, allowlisted payload fields
# ----------------------------------------------------------------------


async def test_request_hits_v1_systemone_with_bearer_and_noul_question():
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_system_one_payload(0.02)), requests
    )
    await backend.triage(_context())
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == SYSTEM_ONE_URL
    assert request.headers["Authorization"] == "Bearer test-typesafe-key"

    body = json.loads(request.content.decode())
    assert body["model"] == JEV_DEFAULT_MODEL
    assert set(body["questions"].keys()) == {"is_threat"}
    assert body["questions"]["is_threat"]["type"] == "noul"
    assert body["questions"]["is_threat"] == JEV_IS_THREAT_QUESTION


async def test_request_body_carries_only_allowlisted_fields():
    """Egress allowlist: only ``model``/``state``/``questions`` leave the host.
    Vercel-era ``providerOptions`` (``disallowPromptTraining``) does not exist on
    the first-party API and must not be sent."""
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_system_one_payload(0.02)), requests
    )
    await backend.triage(_context())
    body = json.loads(requests[0].content.decode())
    assert set(body) == {"model", "state", "questions"}


@pytest.mark.parametrize(
    "base_url,expected",
    [
        ("https://api.typesafe.ai", "https://api.typesafe.ai/v1/systemone"),
        ("https://api.typesafe.ai/", "https://api.typesafe.ai/v1/systemone"),
        (
            "https://typesafe.internal:8443/proxy/",
            "https://typesafe.internal:8443/proxy/v1/systemone",
        ),
    ],
)
async def test_base_url_is_an_api_root_joined_with_systemone_path(
    base_url: str, expected: str
):
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_system_one_payload(0.02)),
        requests,
        base_url=base_url,
    )
    await backend.triage(_context())
    assert str(requests[0].url) == expected


async def test_state_is_tool_arguments_metadata_lines_verbatim():
    """State mirrors the sanitized Tool/Arguments/Metadata shape — the backend
    consumes the pre-sanitized context as-is and never re-sanitizes."""
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_system_one_payload(0.02)), requests
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
    """FR-05: [[PLACEHOLDER]] redactions must reach the TypeSafe API untouched;
    no raw secret material is ever introduced by the backend. Exact-equality
    assertion — substring checks on hostnames trip static analysis."""
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_system_one_payload(0.02)), requests
    )
    context = _context(
        arguments={"token": "[[AWS_SECRET_ACCESS_KEY]]", "host": "wd-bouygues.com"}
    )
    await backend.triage(context)
    state = json.loads(requests[0].content.decode())["state"]
    assert state == (
        "Tool: execute_bash\n"
        "Arguments: {'token': '[[AWS_SECRET_ACCESS_KEY]]', 'host': 'wd-bouygues.com'}\n"
        "Metadata: {}"
    )


# ----------------------------------------------------------------------
# Abstention contract: never fail open, never synthesize a score
# ----------------------------------------------------------------------


async def test_missing_api_key_abstains(monkeypatch):
    monkeypatch.delenv(JEV_API_KEY_ENV_VAR, raising=False)
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_system_one_payload(0.02)),
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
        {"answers": {"is_threat": {"type": "noul"}}},
        {"answers": {"is_threat": {"type": "noul", "noul": "high"}}},
        # A bool is an int subclass in Python — it is not a probability.
        {"answers": {"is_threat": {"type": "noul", "noul": True}}},
        # Vercel-era answer shape must not parse against the first-party API.
        {"answers": {"is_threat": {"type": "boolean", "probability": 0.02}}},
    ],
)
async def test_malformed_system_one_payload_abstains(payload: Dict[str, Any]):
    requests: List[httpx.Request] = []
    backend = _backend(lambda request: httpx.Response(200, json=payload), requests)
    assert await backend.triage(_context()) is None


@pytest.mark.parametrize(
    "probability",
    [
        -1.0,  # negative — out of range
        1.5,  # above range
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
async def test_out_of_range_probability_abstains_never_clamps_into_signal(
    probability: float,
):
    """P1: invalid probabilities must abstain (fail-closed to fallback), never
    clamp into a legitimate-looking 0.0/1.0 signal that bypasses fallback."""
    requests: List[httpx.Request] = []
    payload = {
        "model": JEV_DEFAULT_MODEL,
        "answers": {"is_threat": {"type": "noul", "noul": probability}},
    }
    fallback = _StubFallback(
        result=SemanticTriageResult(threat_score=0.9, backend="gemini")
    )
    backend = _backend(
        lambda request: httpx.Response(200, content=json.dumps(payload)),
        requests,
        fallback=fallback,
    )
    result = await backend.triage(_context())
    assert result is not None
    assert result.backend == "gemini"  # routed through the fail-closed fallback
    assert fallback.calls == 1


async def test_backend_is_a_provider():
    assert issubclass(JevTriageBackend, SemanticTriageProvider)
    assert JevTriageBackend(api_key="k").name == "jev"


def test_env_var_names_match_the_env_example_contract():
    """.env.example is the operator-facing contract; the code must read exactly
    the variable names it documents (ADR 0008)."""
    assert JEV_API_KEY_ENV_VAR == "TYPESAFE_API_KEY"
    assert JEV_BASE_URL_ENV_VAR == "TYPESAFE_BASE_URL"


def test_defaults_match_the_env_example_contract(monkeypatch):
    for name in (
        JEV_API_KEY_ENV_VAR,
        JEV_BASE_URL_ENV_VAR,
        "JEV_MODEL",
        "JEV_TIMEOUT_S",
    ):
        monkeypatch.delenv(name, raising=False)
    backend = JevTriageBackend()
    assert backend.api_key == ""
    assert backend.base_url == "https://api.typesafe.ai"
    assert backend.model == "jev-latest"
    assert backend.timeout == pytest.approx(5.0)


def test_env_example_keeps_jev_latest_unpinned():
    """ADR 0008 Decision 7: ``jev-latest`` is deliberately unpinned. .env.example
    is the operator-facing contract, so it must keep that default as an active
    assignment and must not tell operators to pin (a versioned ID is for a run
    that has to be reproducible or compared against another release)."""
    text = (Path(__file__).resolve().parents[2] / ".env.example").read_text(
        encoding="utf-8"
    )
    lines = text.splitlines()
    assert "JEV_MODEL=jev-latest" in lines
    comment = "\n".join(
        line for line in lines[: lines.index("JEV_MODEL=jev-latest")][-8:]
        if line.startswith("#")
    )
    assert "unpinned" in comment
    assert "Pin a versioned ID" not in text


def test_env_knobs_configure_backend(monkeypatch):
    monkeypatch.setenv(JEV_API_KEY_ENV_VAR, "env-key")
    monkeypatch.setenv(JEV_BASE_URL_ENV_VAR, "https://typesafe.internal")
    monkeypatch.setenv("JEV_MODEL", "jev-1.13.0")
    monkeypatch.setenv("JEV_TIMEOUT_S", "2.5")
    backend = JevTriageBackend()
    assert backend.api_key == "env-key"
    assert backend.base_url == "https://typesafe.internal"
    assert backend.model == "jev-1.13.0"
    assert backend.timeout == pytest.approx(2.5)


def test_blank_env_values_fall_back_to_defaults(monkeypatch):
    """.env.example ships these knobs as active assignments; an operator who
    blanks one (``JEV_MODEL=``) must get the default, not an empty model/URL and
    not a ``float('')`` crash at backend construction."""
    monkeypatch.setenv(JEV_BASE_URL_ENV_VAR, "")
    monkeypatch.setenv("JEV_MODEL", "")
    monkeypatch.setenv("JEV_TIMEOUT_S", "")
    backend = JevTriageBackend(api_key="k")
    assert backend.base_url == JEV_DEFAULT_BASE_URL
    assert backend.model == JEV_DEFAULT_MODEL
    assert backend.timeout == pytest.approx(5.0)


def test_legacy_vercel_env_vars_are_ignored(monkeypatch):
    """A Vercel AI Gateway credential must never be presented to a different
    vendor: no deprecated-alias fallback for the pre-ADR-0008 variables."""
    monkeypatch.delenv(JEV_API_KEY_ENV_VAR, raising=False)
    monkeypatch.delenv(JEV_BASE_URL_ENV_VAR, raising=False)
    monkeypatch.setenv("AI_GATEWAY_API_KEY", "legacy-vercel-credential")
    monkeypatch.setenv("JEV_GATEWAY_URL", "https://legacy-gateway.invalid/v1/evaluate")
    backend = JevTriageBackend()
    assert backend.api_key == ""
    assert backend.base_url == JEV_DEFAULT_BASE_URL
    assert isinstance(build_semantic_provider(object(), "jev"), GeminiTriageBackend)


@pytest.mark.parametrize("removed", ["max_attempts", "backoff_base_s", "backoff_cap_s"])
def test_removed_retry_tuning_params_are_not_accepted(removed: str):
    """The retry budget is a fixed single retry on the paid API (ADR 0008); the
    old free-tier tuning surface must not quietly grow back."""
    with pytest.raises(TypeError):
        JevTriageBackend(api_key="k", **{removed: 1})


# ----------------------------------------------------------------------
# Registry integration (FR-01)
# ----------------------------------------------------------------------


def test_build_semantic_provider_jev_with_key(monkeypatch):
    monkeypatch.setenv(JEV_API_KEY_ENV_VAR, "test-typesafe-key")
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
# Bounded 429/529 backoff + fail-closed fallback (TASK-B02, FR-06)
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
    return httpx.Response(429, json={"message": "rate limit exceeded"})


def _overloaded(request: httpx.Request) -> httpx.Response:
    return httpx.Response(529, json={"message": "temporarily overloaded"})


async def test_429_storm_retries_once_then_falls_back():
    """Paid-API policy (ADR 0008): one retry after a short fixed delay, then
    fail closed to the fallback. Throttling is rare on a paid plan, and this is a
    latency-bounded hot path with a ready fallback, so there is no retry loop."""
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()
    fallback = _StubFallback(
        result=SemanticTriageResult(threat_score=0.9, backend="gemini")
    )
    backend = _backend(_rate_limited, requests, fallback=fallback, sleep=sleep)
    result = await backend.triage(_context())
    assert len(requests) == 2
    assert sleep.calls == [JEV_RETRY_DELAY_S]
    assert fallback.calls == 1
    assert result is not None
    assert result.backend == "gemini"  # signal attributed to its producer
    assert result.threat_score == pytest.approx(0.9)


async def test_429_then_success_retries_once():
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()
    responses = iter(
        [
            httpx.Response(429, json={"message": "slow down"}),
            httpx.Response(200, json=_system_one_payload(0.02)),
        ]
    )
    backend = _backend(lambda request: next(responses), requests, sleep=sleep)
    result = await backend.triage(_context())
    assert len(requests) == 2
    assert sleep.calls == [JEV_RETRY_DELAY_S]
    assert result is not None
    assert result.backend == "jev"
    assert result.threat_score == pytest.approx(0.02)


async def test_529_overloaded_is_retried_once_like_429():
    """TypeSafe documents 429 *and* 529 (Overloaded) as retry-after-a-delay."""
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()
    responses = iter(
        [
            httpx.Response(529, json={"message": "temporarily overloaded"}),
            httpx.Response(200, json=_system_one_payload(0.98)),
        ]
    )
    backend = _backend(lambda request: next(responses), requests, sleep=sleep)
    result = await backend.triage(_context())
    assert len(requests) == 2
    assert sleep.calls == [JEV_RETRY_DELAY_S]
    assert result is not None
    assert result.backend == "jev"
    assert result.threat_score == pytest.approx(0.98)


async def test_529_storm_retries_once_then_falls_back():
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()
    fallback = _StubFallback(
        result=SemanticTriageResult(threat_score=0.9, backend="gemini")
    )
    backend = _backend(_overloaded, requests, fallback=fallback, sleep=sleep)
    result = await backend.triage(_context())
    assert len(requests) == 2
    assert sleep.calls == [JEV_RETRY_DELAY_S]
    assert fallback.calls == 1
    assert result is not None and result.backend == "gemini"


async def test_stale_max_attempts_env_cannot_enlarge_the_retry_budget(monkeypatch):
    """JEV_MAX_ATTEMPTS was removed from .env.example; an old value lingering in
    someone's .env must not turn the single retry back into a retry loop."""
    monkeypatch.setenv("JEV_MAX_ATTEMPTS", "9")
    requests: List[httpx.Request] = []
    backend = _backend(_rate_limited, requests, sleep=_FakeSleep())
    assert await backend.triage(_context()) is None
    assert len(requests) == 2


async def test_timeout_falls_back_immediately_without_retry():
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()

    def _hang(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("typesafe api stalled", request=request)

    fallback = _StubFallback(
        result=SemanticTriageResult(threat_score=0.4, backend="gemini")
    )
    backend = _backend(_hang, requests, fallback=fallback, sleep=sleep)
    result = await backend.triage(_context())
    assert len(requests) == 1  # transient network errors are not retried
    assert sleep.calls == []
    assert fallback.calls == 1
    assert result is not None and result.backend == "gemini"


@pytest.mark.parametrize("status", [400, 401, 413, 422, 500, 503])
async def test_non_transient_status_falls_back_without_retry(status: int):
    """Only the documented transient statuses (429/529) are retried; contract
    errors (400/401/413/422) and other server errors fail closed at once."""
    requests: List[httpx.Request] = []
    sleep = _FakeSleep()
    fallback = _StubFallback(
        result=SemanticTriageResult(threat_score=0.4, backend="gemini")
    )
    backend = _backend(
        lambda request: httpx.Response(status, json={"message": "rejected"}),
        requests,
        fallback=fallback,
        sleep=sleep,
    )
    result = await backend.triage(_context())
    assert len(requests) == 1  # non-transient statuses must never be retried
    assert sleep.calls == []
    assert fallback.calls == 1
    assert result is not None and result.backend == "gemini"


async def test_fallback_failure_abstains_never_allows():
    requests: List[httpx.Request] = []
    fallback = _StubFallback(error=RuntimeError("gemini down"))
    backend = _backend(_rate_limited, requests, fallback=fallback, sleep=_FakeSleep())
    assert await backend.triage(_context()) is None


async def test_429_storm_without_fallback_abstains():
    requests: List[httpx.Request] = []
    backend = _backend(_rate_limited, requests, sleep=_FakeSleep())
    assert await backend.triage(_context()) is None
    assert len(requests) == 2


# ----------------------------------------------------------------------
# Observability (TASK-B03, FR-07): one structured record per triage
# ----------------------------------------------------------------------

SEMANTIC_LOGGER = "blackwall.policy.semantic"


def _triage_records(caplog: Any) -> List[Any]:
    return [r for r in caplog.records if r.message == "jev_triage"]


async def test_success_emits_structured_triage_record(caplog):
    requests: List[httpx.Request] = []
    backend = _backend(
        lambda request: httpx.Response(200, json=_system_one_payload(0.02)),
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
    assert record.confidence is None  # noul answers carry no confidence
    assert record.latency_ms >= 0.0
    assert record.input_tokens == 120
    assert record.output_tokens == 8
    assert record.is_fallback is False


async def test_usage_tokens_are_read_from_snake_case_keys(caplog):
    payload = _system_one_payload(0.98, input_tokens=200, output_tokens=12)
    requests: List[httpx.Request] = []
    backend = _backend(lambda request: httpx.Response(200, json=payload), requests)
    with caplog.at_level(logging.INFO, logger=SEMANTIC_LOGGER):
        await backend.triage(_context())
    record = _triage_records(caplog)[0]
    assert record.input_tokens == 200
    assert record.output_tokens == 12


async def test_missing_or_malformed_usage_records_none_tokens(caplog):
    payload = _system_one_payload(0.02)
    payload["usage"] = {"input_tokens": "many", "output_tokens": None}
    requests: List[httpx.Request] = []
    backend = _backend(lambda request: httpx.Response(200, json=payload), requests)
    with caplog.at_level(logging.INFO, logger=SEMANTIC_LOGGER):
        result = await backend.triage(_context())
    assert result is not None  # usage is telemetry only — never gates the signal
    record = _triage_records(caplog)[0]
    assert record.input_tokens is None
    assert record.output_tokens is None


async def test_fallback_emits_honest_is_fallback_record(caplog):
    requests: List[httpx.Request] = []
    fallback = _StubFallback(
        result=SemanticTriageResult(threat_score=0.9, backend="gemini")
    )
    backend = _backend(_rate_limited, requests, fallback=fallback, sleep=_FakeSleep())
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


async def test_total_abstention_emits_abstention_record(caplog):
    """FR-07: degraded triages must still record — outage, latency, and budget
    baselines omit nothing. Abstain shape: p/confidence None, backend 'jev',
    is_fallback False when no fallback is configured."""
    requests: List[httpx.Request] = []
    backend = _backend(_rate_limited, requests, sleep=_FakeSleep())
    with caplog.at_level(logging.INFO, logger=SEMANTIC_LOGGER):
        assert await backend.triage(_context()) is None
    records = _triage_records(caplog)
    assert len(records) == 1
    record = records[0]
    assert record.backend == "jev"
    assert record.p is None
    assert record.confidence is None
    assert record.latency_ms >= 0.0
    assert record.input_tokens is None
    assert record.output_tokens is None
    assert record.is_fallback is False


async def test_failed_fallback_abstention_records_is_fallback_true(caplog):
    requests: List[httpx.Request] = []
    fallback = _StubFallback(error=RuntimeError("gemini down"))
    backend = _backend(_rate_limited, requests, fallback=fallback, sleep=_FakeSleep())
    with caplog.at_level(logging.INFO, logger=SEMANTIC_LOGGER):
        assert await backend.triage(_context()) is None
    record = _triage_records(caplog)[0]
    assert record.is_fallback is True
    assert record.p is None


# ----------------------------------------------------------------------
# HTTP client lifecycle: owned clients close, injected clients survive
# ----------------------------------------------------------------------


async def test_aclose_closes_owned_client():
    backend = JevTriageBackend(api_key="k")  # no injected client -> owns it
    mock_client = AsyncMock()
    backend._http_client = mock_client
    await backend.aclose()
    mock_client.aclose.assert_awaited_once()
    assert backend._http_client is None


async def test_aclose_skips_injected_client():
    injected = AsyncMock()
    backend = JevTriageBackend(api_key="k", http_client=injected)
    await backend.aclose()
    injected.aclose.assert_not_awaited()
    assert backend._http_client is injected


async def test_aclose_without_client_is_a_noop():
    backend = JevTriageBackend(api_key="k")
    await backend.aclose()  # never created a client


async def test_resolver_close_closes_owned_jev_provider_client(monkeypatch):
    """Greptile P2: SyncResolver.close() must reach the semantic provider so
    repeatedly created resolvers cannot leak API connection pools."""
    from blackwall.sync_resolver import SyncResolver

    monkeypatch.setenv(JEV_API_KEY_ENV_VAR, "test-typesafe-key")
    resolver = SyncResolver(client=MagicMock(), semantic_backend="jev")
    provider = resolver.semantic_provider
    assert isinstance(provider, JevTriageBackend)
    mock_client = AsyncMock()
    provider._http_client = mock_client
    await resolver.close()
    mock_client.aclose.assert_awaited_once()

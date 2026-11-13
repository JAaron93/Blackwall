"""Tier-1 is Jev only and fails fast (ADR 0009).

There is no fallback backend, no abstention and no backend selection. Any
reason Jev cannot answer (no key, HTTP error, throttle that outlasts the single
retry, transport error, malformed or out-of-range payload) raises
``JevUnavailableError``. The resolver never turns that into ALLOW or into a
synthetic score.
"""

from typing import Any, Callable, Dict, List
from unittest.mock import AsyncMock

import httpx
import pytest

from blackwall import sync_resolver
from blackwall.models import ToolCallContext
from blackwall.policy import semantic
from blackwall.policy.semantic import (
    JEV_DEFAULT_BASE_URL,
    JEV_DEFAULT_MODEL,
    JevTriageBackend,
    JevUnavailableError,
    SemanticTriageProvider,
    SemanticTriageResult,
)
from blackwall.sync_resolver import SyncResolver

REMOVED_NAMES = (
    "GeminiTriageBackend",
    "SEMANTIC_TRIAGE_BACKENDS",
    "SEMANTIC_BACKEND_ENV_VAR",
    "DEFAULT_SEMANTIC_BACKEND",
    "PENDING_SEMANTIC_BACKENDS",
    "resolve_semantic_backend",
    "build_semantic_provider",
)


def _context() -> ToolCallContext:
    return ToolCallContext(tool_name="execute_bash", arguments={"cmd": "ls"})


def _ok(p: float) -> Dict[str, Any]:
    return {
        "model": JEV_DEFAULT_MODEL,
        "answers": {"is_threat": {"type": "noul", "noul": p}},
        "usage": {"input_tokens": 10, "output_tokens": 2},
    }


def _backend(handler: Callable[[httpx.Request], httpx.Response], **kw: Any):
    kw.setdefault("api_key", "test-typesafe-key")
    kw.setdefault("base_url", JEV_DEFAULT_BASE_URL)
    kw.setdefault("model", JEV_DEFAULT_MODEL)
    kw.setdefault("timeout", 5.0)
    kw.setdefault("sleep", AsyncMock())
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return JevTriageBackend(http_client=client, **kw)


# ----------------------------------------------------------------------
# Every unavailability raises
# ----------------------------------------------------------------------


def test_missing_key_raises_at_construction(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    with pytest.raises(JevUnavailableError):
        JevTriageBackend()


def test_blank_key_raises_at_construction(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "   ")
    with pytest.raises(JevUnavailableError):
        JevTriageBackend()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 403, 500, 503])
async def test_http_error_raises(status):
    backend = _backend(lambda r: httpx.Response(status, json={"error": "x"}))
    with pytest.raises(JevUnavailableError):
        await backend.triage(_context())


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 529])
async def test_throttle_retries_once_then_raises(status):
    calls: List[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(status, json={"error": "busy"})

    sleep = AsyncMock()
    backend = _backend(_handler, sleep=sleep)
    with pytest.raises(JevUnavailableError):
        await backend.triage(_context())
    assert len(calls) == 2
    sleep.assert_awaited_once()


@pytest.mark.asyncio
async def test_throttle_then_success_still_returns_a_result():
    responses = iter([httpx.Response(429, json={}), httpx.Response(200, json=_ok(0.6))])
    backend = _backend(lambda r: next(responses))
    result = await backend.triage(_context())
    assert result is not None and result.threat_score == pytest.approx(0.6)


@pytest.mark.asyncio
async def test_transport_error_raises():
    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    with pytest.raises(JevUnavailableError):
        await _backend(_boom).triage(_context())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"answers": {}},
        {"answers": {"is_threat": {"type": "noul"}}},
        {"answers": {"is_threat": {"type": "noul", "noul": "high"}}},
        {"answers": {"is_threat": {"type": "noul", "noul": True}}},
        {"answers": {"is_threat": {"type": "noul", "noul": 1.2}}},
        {"answers": {"is_threat": {"type": "noul", "noul": -0.1}}},
        {"answers": {"is_threat": {"type": "noul", "noul": float("nan")}}},
    ],
)
async def test_malformed_or_out_of_range_payload_raises(payload):
    backend = _backend(lambda r: httpx.Response(200, json=payload))
    with pytest.raises(JevUnavailableError):
        await backend.triage(_context())


@pytest.mark.asyncio
async def test_non_json_body_raises():
    backend = _backend(lambda r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(JevUnavailableError):
        await backend.triage(_context())


@pytest.mark.asyncio
async def test_valid_answer_is_returned_unchanged():
    result = await _backend(lambda r: httpx.Response(200, json=_ok(0.5))).triage(
        _context()
    )
    assert result is not None
    assert (result.threat_score, result.backend, result.escalate) == (0.5, "jev", True)


def test_error_message_never_contains_the_key():
    backend = _backend(lambda r: httpx.Response(500), api_key="sk-secret-value-123")
    import asyncio

    with pytest.raises(JevUnavailableError) as info:
        asyncio.run(backend.triage(_context()))
    assert "sk-secret-value-123" not in str(info.value)


# ----------------------------------------------------------------------
# No fallback, no selection
# ----------------------------------------------------------------------


def test_fallback_parameter_is_gone():
    with pytest.raises(TypeError):
        JevTriageBackend(api_key="k", fallback=object())  # type: ignore[call-arg]


@pytest.mark.parametrize("name", REMOVED_NAMES)
def test_removed_names_are_not_importable(name):
    assert not hasattr(semantic, name)


def test_policy_package_no_longer_exports_removed_names():
    from blackwall import policy

    for name in REMOVED_NAMES:
        assert not hasattr(policy, name)
        assert name not in getattr(policy, "__all__", ())


def test_resolver_has_no_backend_selection(monkeypatch):
    monkeypatch.setenv("BW_SEMANTIC_BACKEND", "gemini")
    with pytest.raises(TypeError):
        SyncResolver(semantic_backend="gemini")  # type: ignore[call-arg]
    assert not hasattr(sync_resolver, "SEMANTIC_BACKEND_ENV_VAR")


def test_provider_contract_has_no_abstain_return():
    ann = SemanticTriageProvider.triage.__annotations__["return"]
    assert "None" not in str(ann)


# ----------------------------------------------------------------------
# Resolver: propagates, never allows, needs no Gemini client for Tier-1
# ----------------------------------------------------------------------


class _Down(SemanticTriageProvider):
    name = "jev"

    async def triage(self, context: ToolCallContext) -> SemanticTriageResult:
        raise JevUnavailableError("Jev is down")


class _Fixed(SemanticTriageProvider):
    name = "jev"

    def __init__(self, p: float) -> None:
        self.p = p

    async def triage(self, context: ToolCallContext) -> SemanticTriageResult:
        return SemanticTriageResult(threat_score=self.p, backend="jev")


@pytest.mark.asyncio
async def test_evaluate_propagates_jev_failure():
    resolver = SyncResolver(client=None, enable_semantic_triage=True)
    resolver._semantic_provider = _Down()
    with pytest.raises(JevUnavailableError):
        await resolver.evaluate(_context())


@pytest.mark.asyncio
async def test_evaluate_with_triage_disabled_never_touches_jev():
    resolver = SyncResolver(client=None, enable_semantic_triage=False)
    resolver._semantic_provider = _Down()
    verdict = await resolver.evaluate(_context())
    assert verdict is not None


@pytest.mark.asyncio
async def test_tier1_runs_without_a_gemini_client():
    resolver = SyncResolver(client=None, enable_semantic_triage=True)
    stub = _Fixed(0.9)
    resolver._semantic_provider = stub
    verdict = await resolver.evaluate(_context())
    assert verdict is not None
    assert resolver.tier2_calls == 0


@pytest.mark.asyncio
async def test_enabled_triage_without_key_fails_on_first_use(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    resolver = SyncResolver(client=None, enable_semantic_triage=True)
    with pytest.raises(JevUnavailableError):
        await resolver.evaluate(_context())

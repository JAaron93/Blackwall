"""Unit tests for the Jev Tier-1 triage backend (TASK-B01, FR-02/FR-05/NFR-06).

Governing spec: .kiro/specs/tier-1-jev-addition/

The Gateway is mocked via ``httpx.MockTransport`` — no live calls in unit
tests (NFR-03); live Jev traffic is eval-harness-only.
"""

import json
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
    kwargs.setdefault("api_key", "test-gateway-key")
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

"""
Unit tests for WebhookListener security and lifecycle (test_webhook_security.py).

Covers:
  1. test_init_stores_configuration          — __init__ stores db, gemini_client, audience, port
  2. test_handle_webhook_valid_signature     — valid JWT triggers _process_payload via background task
  3. test_handle_webhook_invalid_signature   — tampered/invalid JWT is rejected with 400
  4. test_handle_webhook_missing_signature_header — missing Webhook-Signature header → 400
  5. test_verify_signature_correct_hmac      — known RS256 JWT is accepted end-to-end
  6. test_verify_signature_tampered_payload  — JWT bound to a different interaction_id → 400
  7. test_process_payload_valid_event        — _process_payload stores signatures for known task
  8. test_process_payload_unknown_event_type — _process_payload discards unknown task gracefully
  9. test_get_public_key_caching             — JWKS is only fetched once; second call uses cache
 10. test_start_stop_lifecycle               — start()/stop() run cleanly without errors
"""

import asyncio
import base64
import json
import os
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from blackwall.api.webhook_listener import WebhookListener


# ---------------------------------------------------------------------------
# Session-scoped RSA key pair (generated once – RSA key-gen is slow)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def rsa_key_pair():
    """Generate an RSA-2048 key pair once per test session."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()

    def _int_to_b64url(val: int) -> str:
        byte_len = (val.bit_length() + 7) // 8
        raw = val.to_bytes(byte_len, byteorder="big")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "unit-test-kid",
                "use": "sig",
                "alg": "RS256",
                "n": _int_to_b64url(numbers.n),
                "e": _int_to_b64url(numbers.e),
            }
        ]
    }
    return private_key, jwks


# ---------------------------------------------------------------------------
# Helpers to build a minimal WebhookListener with mocked dependencies
# ---------------------------------------------------------------------------


def _make_listener(audience: str = "test-audience") -> WebhookListener:
    """Return a WebhookListener with fully mocked db and gemini_client."""
    mock_db = MagicMock()
    mock_db.is_task_valid = AsyncMock(return_value=True)
    mock_db.write_signatures_batch = AsyncMock()
    mock_db.remove_in_flight_task = AsyncMock()

    mock_gemini = MagicMock()
    mock_gemini.interactions = MagicMock()
    mock_gemini.interactions.get = AsyncMock(
        return_value={
            "task_id": "task-001",
            "threat_signature_candidates": [
                {"payloadPattern": "malicious_pattern", "attackerIntent": "exfiltrate"}
            ],
        }
    )

    with patch.dict(os.environ, {"GEMINI_WEBHOOK_AUDIENCE": audience}, clear=False):
        listener = WebhookListener(mock_db, gemini_client=mock_gemini, audience=audience)

    return listener


def _make_jwks_mock(jwks: dict):
    """Return a context-manager-compatible mock that patches JWKS HTTP calls."""

    class _MockResp:
        status = 200

        async def json(self):
            return jwks

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    patcher = patch("aiohttp.ClientSession.get", return_value=_MockResp())
    return patcher


def _mint_jwt(
    private_key,
    interaction_id: str,
    audience: str = "test-audience",
    kid: str = "unit-test-kid",
    extra_claims: dict | None = None,
) -> str:
    """Mint a valid RS256 JWT bound to *interaction_id*."""
    claims = {
        "iss": "google",
        "aud": audience,
        "exp": int(time.time()) + 3600,
        "sub": interaction_id,
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": kid, "alg": "RS256"},
    )


def _build_request_mock(
    *,
    token: str = "",
    timestamp: str | None = None,
    webhook_id: str | None = None,
    payload: dict | None = None,
) -> MagicMock:
    """
    Build a minimal aiohttp.web.Request mock for use with handle_webhook().

    All mutable defaults are resolved at call time to avoid shared-state bugs.
    """
    if timestamp is None:
        timestamp = str(time.time())
    if webhook_id is None:
        webhook_id = str(uuid.uuid4())
    if payload is None:
        interaction_id = str(uuid.uuid4())
        payload = {
            "type": "interaction.completed",
            "data": {"id": interaction_id},
        }

    payload_bytes = json.dumps(payload).encode("utf-8")

    request = MagicMock()
    request.headers = {
        "Webhook-Signature": token,
        "webhook-timestamp": timestamp,
        "webhook-id": webhook_id,
    }
    request.read = AsyncMock(return_value=payload_bytes)
    return request, payload


# ===========================================================================
# 1. test_init_stores_configuration
# ===========================================================================


def test_init_stores_configuration():
    """WebhookListener.__init__ stores db, gemini_client, audience, and port."""
    mock_db = MagicMock()
    mock_gemini = MagicMock()
    test_audience = "my-unique-audience"

    with patch.dict(
        os.environ,
        {"GEMINI_WEBHOOK_AUDIENCE": test_audience, "BLACKWALL_WEBHOOK_PORT": "9999"},
        clear=False,
    ):
        listener = WebhookListener(
            mock_db, gemini_client=mock_gemini, audience=test_audience
        )

    assert listener.db is mock_db
    assert listener.gemini_client is mock_gemini
    assert listener.audience == test_audience
    # Port is read from env at construction time
    assert listener.port == 9999

    # Deduplication structures are initialised empty
    assert len(listener.processed_webhooks) == 0
    assert len(listener.processed_webhooks_queue) == 0


# ===========================================================================
# 2. test_handle_webhook_valid_signature
# ===========================================================================


@pytest.mark.asyncio
async def test_handle_webhook_valid_signature(rsa_key_pair):
    """
    A correctly-signed webhook with all required headers must return 200
    and schedule _process_payload as a background task.
    """
    private_key, jwks = rsa_key_pair
    listener = _make_listener()

    interaction_id = str(uuid.uuid4())
    token = _mint_jwt(private_key, interaction_id)
    payload = {"type": "interaction.completed", "data": {"id": interaction_id}}
    payload_bytes = json.dumps(payload).encode("utf-8")

    request = MagicMock()
    request.headers = {
        "Webhook-Signature": token,
        "webhook-timestamp": str(time.time()),
        "webhook-id": str(uuid.uuid4()),
    }
    request.read = AsyncMock(return_value=payload_bytes)

    process_called = asyncio.Event()
    original_process = listener._process_payload

    async def _tracking_process(interaction_id_arg, latency):
        process_called.set()
        # Delegate to original to avoid interfering with other assertions
        await original_process(interaction_id_arg, latency)

    listener._process_payload = _tracking_process

    with _make_jwks_mock(jwks):
        response = await listener.handle_webhook(request)

    assert response.status == 200

    # Allow the background task to run
    if listener.background_tasks:
        await asyncio.wait(listener.background_tasks, timeout=2.0)

    assert process_called.is_set(), "_process_payload was not invoked for a valid webhook"


# ===========================================================================
# 3. test_handle_webhook_invalid_signature
# ===========================================================================


@pytest.mark.asyncio
async def test_handle_webhook_invalid_signature(rsa_key_pair):
    """
    A JWT signed with a different (unknown) RSA key must be rejected with 400
    and must NOT schedule any background processing.
    """
    _, jwks = rsa_key_pair
    listener = _make_listener()

    interaction_id = str(uuid.uuid4())

    # Mint the token with a *different* private key – JWKS has the original pubkey
    attacker_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    bad_token = jwt.encode(
        {
            "aud": "test-audience",
            "exp": int(time.time()) + 3600,
            "sub": interaction_id,
        },
        attacker_private_key,
        algorithm="RS256",
        headers={"kid": "unit-test-kid", "alg": "RS256"},
    )

    payload = {"type": "interaction.completed", "data": {"id": interaction_id}}
    payload_bytes = json.dumps(payload).encode("utf-8")

    request = MagicMock()
    request.headers = {
        "Webhook-Signature": bad_token,
        "webhook-timestamp": str(time.time()),
        "webhook-id": str(uuid.uuid4()),
    }
    request.read = AsyncMock(return_value=payload_bytes)

    with _make_jwks_mock(jwks):
        response = await listener.handle_webhook(request)

    assert response.status == 400
    assert len(listener.background_tasks) == 0


# ===========================================================================
# 4. test_handle_webhook_missing_signature_header
# ===========================================================================


@pytest.mark.asyncio
async def test_handle_webhook_missing_signature_header():
    """
    A request missing the Webhook-Signature header must be rejected with 400
    (the spec states 401/403 intent; the implementation uses 400 / Bad Request).
    """
    listener = _make_listener()

    payload = {"type": "interaction.completed", "data": {"id": str(uuid.uuid4())}}
    payload_bytes = json.dumps(payload).encode("utf-8")

    request = MagicMock()
    # Deliberately omit "Webhook-Signature"
    request.headers = {
        "webhook-timestamp": str(time.time()),
        "webhook-id": str(uuid.uuid4()),
    }
    request.read = AsyncMock(return_value=payload_bytes)

    response = await listener.handle_webhook(request)

    assert response.status == 400


@pytest.mark.asyncio
async def test_handle_webhook_missing_timestamp_header():
    """A request missing the webhook-timestamp header must be rejected with 400."""
    listener = _make_listener()

    request = MagicMock()
    request.headers = {
        "Webhook-Signature": "any-token",
        # missing "webhook-timestamp"
        "webhook-id": str(uuid.uuid4()),
    }
    request.read = AsyncMock(return_value=b"{}")

    response = await listener.handle_webhook(request)
    assert response.status == 400


@pytest.mark.asyncio
async def test_handle_webhook_missing_webhook_id_header():
    """A request missing the webhook-id header must be rejected with 400."""
    listener = _make_listener()

    request = MagicMock()
    request.headers = {
        "Webhook-Signature": "any-token",
        "webhook-timestamp": str(time.time()),
        # missing "webhook-id"
    }
    request.read = AsyncMock(return_value=b"{}")

    response = await listener.handle_webhook(request)
    assert response.status == 400


# ===========================================================================
# 5. test_verify_signature_correct_hmac  (RS256 end-to-end equivalent)
# ===========================================================================


@pytest.mark.asyncio
async def test_verify_signature_correct_hmac(rsa_key_pair):
    """
    A valid RS256 JWT with correct audience, exp, and sub matching payload.data.id
    must be accepted end-to-end (handle_webhook returns 200).

    This is the RS256 analogue of the "correct HMAC" test: it validates that
    the cryptographic signature check passes for a known-good key + payload.
    """
    private_key, jwks = rsa_key_pair
    listener = _make_listener(audience="test-audience")

    interaction_id = str(uuid.uuid4())
    token = _mint_jwt(private_key, interaction_id, audience="test-audience")
    payload = {"type": "interaction.completed", "data": {"id": interaction_id}}

    request = MagicMock()
    request.headers = {
        "Webhook-Signature": token,
        "webhook-timestamp": str(time.time()),
        "webhook-id": str(uuid.uuid4()),
    }
    request.read = AsyncMock(return_value=json.dumps(payload).encode("utf-8"))

    with _make_jwks_mock(jwks):
        response = await listener.handle_webhook(request)

    assert response.status == 200, (
        "Expected 200 for a correctly-signed RS256 webhook but got "
        f"{response.status}"
    )


# ===========================================================================
# 6. test_verify_signature_tampered_payload
# ===========================================================================


@pytest.mark.asyncio
async def test_verify_signature_tampered_payload(rsa_key_pair):
    """
    When the JWT's `sub` claim names a *different* interaction_id than the
    payload's `data.id`, the bind-check must fail and return 400.
    """
    private_key, jwks = rsa_key_pair
    listener = _make_listener()

    jwt_interaction_id = str(uuid.uuid4())
    tampered_interaction_id = str(uuid.uuid4())  # different from JWT's sub

    token = _mint_jwt(private_key, jwt_interaction_id)
    # Payload references a DIFFERENT interaction_id → JWT bind check fails
    payload = {
        "type": "interaction.completed",
        "data": {"id": tampered_interaction_id},
    }

    request = MagicMock()
    request.headers = {
        "Webhook-Signature": token,
        "webhook-timestamp": str(time.time()),
        "webhook-id": str(uuid.uuid4()),
    }
    request.read = AsyncMock(return_value=json.dumps(payload).encode("utf-8"))

    with _make_jwks_mock(jwks):
        response = await listener.handle_webhook(request)

    assert response.status == 400


# ===========================================================================
# 7. test_process_payload_valid_event  (analysis_complete / known task)
# ===========================================================================


@pytest.mark.asyncio
async def test_process_payload_valid_event():
    """
    _process_payload for a known task_id must:
      - call gemini_client.interactions.get
      - call db.write_signatures_batch
      - call db.remove_in_flight_task
    """
    listener = _make_listener()
    interaction_id = str(uuid.uuid4())

    # Patch the OpenTelemetry tracer so we don't need a real OTEL provider
    with patch(
        "blackwall.api.webhook_listener.tracer.start_as_current_span"
    ) as mock_span_ctx:
        mock_span = MagicMock()
        mock_span.set_attribute = MagicMock()
        mock_span.set_status = MagicMock()
        mock_span_ctx.return_value.__enter__ = MagicMock(return_value=mock_span)
        mock_span_ctx.return_value.__exit__ = MagicMock(return_value=False)

        await listener._process_payload(interaction_id, 10.0)

    listener.gemini_client.interactions.get.assert_awaited_once_with(interaction_id)
    listener.db.write_signatures_batch.assert_awaited_once()
    listener.db.remove_in_flight_task.assert_awaited_once_with("task-001")


# ===========================================================================
# 8. test_process_payload_unknown_event_type  (unknown / stale task)
# ===========================================================================


@pytest.mark.asyncio
async def test_process_payload_unknown_event_type():
    """
    _process_payload for an *unknown* task_id (is_task_valid returns False)
    must discard the interaction without writing signatures.
    """
    mock_db = MagicMock()
    mock_db.is_task_valid = AsyncMock(return_value=False)  # Simulate stale/unknown task
    mock_db.write_signatures_batch = AsyncMock()
    mock_db.remove_in_flight_task = AsyncMock()

    mock_gemini = MagicMock()
    mock_gemini.interactions = MagicMock()
    mock_gemini.interactions.get = AsyncMock(
        return_value={
            "task_id": "unknown-task-xyz",
            "threat_signature_candidates": [{"payloadPattern": "should-not-be-written"}],
        }
    )

    with patch.dict(os.environ, {"GEMINI_WEBHOOK_AUDIENCE": "test-audience"}, clear=False):
        listener = WebhookListener(
            mock_db, gemini_client=mock_gemini, audience="test-audience"
        )

    interaction_id = str(uuid.uuid4())

    with patch(
        "blackwall.api.webhook_listener.tracer.start_as_current_span"
    ) as mock_span_ctx:
        mock_span = MagicMock()
        mock_span.set_attribute = MagicMock()
        mock_span.set_status = MagicMock()
        mock_span_ctx.return_value.__enter__ = MagicMock(return_value=mock_span)
        mock_span_ctx.return_value.__exit__ = MagicMock(return_value=False)

        await listener._process_payload(interaction_id, 5.0)

    # Signatures MUST NOT be written for an unknown/stale task
    mock_db.write_signatures_batch.assert_not_awaited()
    # in-flight removal MUST NOT be called either
    mock_db.remove_in_flight_task.assert_not_awaited()


# ===========================================================================
# 9. test_get_public_key_caching
# ===========================================================================


@pytest.mark.asyncio
async def test_get_public_key_caching(rsa_key_pair):
    """
    _get_public_key must fetch JWKS only once and return the cached key on
    subsequent calls within the cache TTL window.
    """
    private_key, jwks = rsa_key_pair
    listener = _make_listener()

    fetch_count = 0

    class _CountingResp:
        status = 200

        async def json(self):
            nonlocal fetch_count
            fetch_count += 1
            return jwks

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    with patch("aiohttp.ClientSession.get", return_value=_CountingResp()):
        key1 = await listener._get_public_key("unit-test-kid")
        key2 = await listener._get_public_key("unit-test-kid")

    assert key1 is key2, "Subsequent calls must return the exact same cached key object"
    assert fetch_count == 1, (
        f"JWKS endpoint was fetched {fetch_count} times; expected exactly 1"
    )


@pytest.mark.asyncio
async def test_get_public_key_raises_for_missing_kid(rsa_key_pair):
    """_get_public_key must raise ValueError when the kid is absent from JWKS."""
    _, jwks = rsa_key_pair
    listener = _make_listener()

    class _MockResp:
        status = 200

        async def json(self):
            return jwks

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    with patch("aiohttp.ClientSession.get", return_value=_MockResp()):
        with pytest.raises(ValueError, match="not found in JWKS"):
            await listener._get_public_key("nonexistent-kid")


# ===========================================================================
# 10. test_start_stop_lifecycle
# ===========================================================================


@pytest.mark.asyncio
async def test_start_stop_lifecycle():
    """
    start() and stop() must complete without raising exceptions, and stop()
    must be idempotent when called on a never-started listener.
    """
    listener = _make_listener()

    # Patch aiohttp server components so no real TCP socket is opened
    with (
        patch("aiohttp.web.AppRunner") as MockRunner,
        patch("aiohttp.web.TCPSite") as MockSite,
    ):
        mock_runner_instance = AsyncMock()
        MockRunner.return_value = mock_runner_instance

        mock_site_instance = AsyncMock()
        MockSite.return_value = mock_site_instance

        await listener.start()

        # Verify setup and start were called
        mock_runner_instance.setup.assert_awaited_once()
        mock_site_instance.start.assert_awaited_once()

        await listener.stop()

        # Verify cleanup was called
        mock_runner_instance.cleanup.assert_awaited_once()


@pytest.mark.asyncio
async def test_stop_with_no_runner_does_not_raise():
    """
    Calling stop() on a listener that was never started (runner is None)
    must not raise any exceptions.
    """
    listener = _make_listener()
    assert listener.runner is None

    # Should complete without raising
    await listener.stop()


@pytest.mark.asyncio
async def test_stop_waits_for_background_tasks():
    """
    stop() must wait for in-flight background tasks to complete before
    returning (up to the 30 s timeout).
    """
    listener = _make_listener()
    listener.runner = AsyncMock()
    listener.runner.cleanup = AsyncMock()

    finished = asyncio.Event()

    async def _slow_task():
        await asyncio.sleep(0.05)
        finished.set()

    task = asyncio.create_task(_slow_task())
    listener.background_tasks.add(task)
    task.add_done_callback(listener.background_tasks.discard)

    await listener.stop()

    assert finished.is_set(), "stop() returned before the background task finished"


# ===========================================================================
# Bonus: JWT bound to interaction_id via `interaction_id` claim (not `sub`)
# ===========================================================================


@pytest.mark.asyncio
async def test_handle_webhook_interaction_id_claim_binding(rsa_key_pair):
    """
    The JWT bind-check must also pass when interaction_id claim (not sub)
    matches the payload's data.id.
    """
    private_key, jwks = rsa_key_pair
    listener = _make_listener(audience="test-audience")

    interaction_id = str(uuid.uuid4())
    # Omit 'sub'; use 'interaction_id' claim instead
    claims = {
        "iss": "google",
        "aud": "test-audience",
        "exp": int(time.time()) + 3600,
        "interaction_id": interaction_id,
        # deliberately no 'sub'
        "sub": "",
    }
    token = jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": "unit-test-kid", "alg": "RS256"},
    )
    payload = {"type": "interaction.completed", "data": {"id": interaction_id}}

    request = MagicMock()
    request.headers = {
        "Webhook-Signature": token,
        "webhook-timestamp": str(time.time()),
        "webhook-id": str(uuid.uuid4()),
    }
    request.read = AsyncMock(return_value=json.dumps(payload).encode("utf-8"))

    with _make_jwks_mock(jwks):
        response = await listener.handle_webhook(request)

    assert response.status == 200


# ===========================================================================
# Bonus: Stale timestamp rejection (replay-attack guard)
# ===========================================================================


@pytest.mark.asyncio
async def test_handle_webhook_stale_timestamp_rejected(rsa_key_pair):
    """
    A timestamp older than 5 minutes (300 s) must be rejected with 400
    regardless of JWT validity.
    """
    private_key, jwks = rsa_key_pair
    listener = _make_listener()

    interaction_id = str(uuid.uuid4())
    token = _mint_jwt(private_key, interaction_id)
    payload = {"type": "interaction.completed", "data": {"id": interaction_id}}

    stale_ts = str(time.time() - 301)

    request = MagicMock()
    request.headers = {
        "Webhook-Signature": token,
        "webhook-timestamp": stale_ts,
        "webhook-id": str(uuid.uuid4()),
    }
    request.read = AsyncMock(return_value=json.dumps(payload).encode("utf-8"))

    with _make_jwks_mock(jwks):
        response = await listener.handle_webhook(request)

    assert response.status == 400


# ===========================================================================
# Bonus: Deduplication — duplicate webhook-id returns 200 without re-processing
# ===========================================================================


@pytest.mark.asyncio
async def test_handle_webhook_deduplication(rsa_key_pair):
    """
    A second webhook arriving with the same webhook-id (after the first
    succeeds) must be silently accepted (200 OK) without re-processing.
    """
    private_key, jwks = rsa_key_pair
    listener = _make_listener()

    interaction_id = str(uuid.uuid4())
    token = _mint_jwt(private_key, interaction_id)
    webhook_id = str(uuid.uuid4())
    payload = {"type": "interaction.completed", "data": {"id": interaction_id}}
    payload_bytes = json.dumps(payload).encode("utf-8")

    def _make_req():
        req = MagicMock()
        req.headers = {
            "Webhook-Signature": token,
            "webhook-timestamp": str(time.time()),
            "webhook-id": webhook_id,
        }
        req.read = AsyncMock(return_value=payload_bytes)
        return req

    with _make_jwks_mock(jwks):
        resp1 = await listener.handle_webhook(_make_req())
        assert resp1.status == 200

        # Wait for background tasks from the first request
        if listener.background_tasks:
            await asyncio.wait(listener.background_tasks, timeout=2.0)

        # Second identical webhook-id
        resp2 = await listener.handle_webhook(_make_req())
        assert resp2.status == 200

    # interactions.get must have been called only once (first request only)
    assert listener.gemini_client.interactions.get.await_count == 1

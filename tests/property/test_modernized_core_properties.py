"""Property-based tests for modernized core integrations.

Properties verified using Hypothesis:
1. Vault HKDF Encryption Roundtrip Invariant:
   save(data) -> load() == data for arbitrary keys and payloads.
2. Vault Legacy SHA-256 Compatibility Invariant:
   Payloads encrypted with legacy SHA-256 key derivation are always successfully loaded.
3. Vault File Permissions Invariant:
   Vault saves always produce files with 0o600 restricted permissions.
4. Certifi SSLContext Caching Identity Invariant:
   Successive calls to get_certifi_ssl_context() return the identical cached instance.
5. PolicyFileHandler Debounce Coalescing Invariant:
   Any rapid event burst within the debounce interval executes at most one immediate callback.
6. SyncResolver Client AIO Dispatch Invariant:
   When client.aio is present, semantic evaluations invoke client.aio directly without thread-pool dispatch.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet
from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.mcp.transport import get_certifi_ssl_context
from blackwall.models import ToolCallContext
from blackwall.policy.watcher import PolicyFileHandler
from blackwall.security.vault import EncryptedLocalStore
from blackwall.sync_resolver import SemanticTriageEvaluation, SyncResolver

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

safe_key_st = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
    min_size=1,
    max_size=32,
)

safe_secret_dict_st = st.dictionaries(
    keys=safe_key_st,
    values=st.text(min_size=0, max_size=100),
    min_size=1,
    max_size=10,
)


# ---------------------------------------------------------------------------
# Property 1: Vault HKDF Round-trip Invariant
# ---------------------------------------------------------------------------

@settings(max_examples=30, deadline=None)
@given(master_key=safe_key_st, secrets=safe_secret_dict_st)
def test_vault_hkdf_roundtrip_property(master_key: str, secrets: dict[str, str]) -> None:
    """Property: For any master key and secret payload, save -> load is lossless."""
    with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as tf:
        filepath = tf.name

    try:
        store = EncryptedLocalStore(filepath, master_key=master_key)
        store.save(secrets)
        loaded = store.load()
        assert loaded == secrets
    finally:
        if os.path.exists(filepath):
            os.unlink(filepath)


# ---------------------------------------------------------------------------
# Property 2: Vault Legacy SHA-256 Compatibility Invariant
# ---------------------------------------------------------------------------

@settings(max_examples=30, deadline=None)
@given(master_key=safe_key_st, secrets=safe_secret_dict_st)
def test_vault_legacy_sha256_compatibility_property(master_key: str, secrets: dict[str, str]) -> None:
    """Property: Any payload encrypted with legacy raw SHA-256 is decrypted losslessly."""
    with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as tf:
        filepath = tf.name

    try:
        # Create legacy ciphertext
        key_bytes = master_key.encode("utf-8")
        legacy_key = base64.urlsafe_b64encode(hashlib.sha256(key_bytes).digest())
        cipher = Fernet(legacy_key)
        raw_bytes = json.dumps(secrets).encode("utf-8")
        encrypted = cipher.encrypt(raw_bytes)

        with open(filepath, "wb") as f:
            f.write(encrypted)

        # Load with modern HKDF-capable store
        store = EncryptedLocalStore(filepath, master_key=master_key)
        loaded = store.load()
        assert loaded == secrets
    finally:
        if os.path.exists(filepath):
            os.unlink(filepath)


# ---------------------------------------------------------------------------
# Property 3: Vault File Permissions Invariant
# ---------------------------------------------------------------------------

@settings(max_examples=25, deadline=None)
@given(master_key=safe_key_st, secrets=safe_secret_dict_st)
def test_vault_file_permissions_property(master_key: str, secrets: dict[str, str]) -> None:
    """Property: Saved vault files always possess 0o600 restricted permissions."""
    with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as tf:
        filepath = tf.name

    try:
        store = EncryptedLocalStore(filepath, master_key=master_key)
        store.save(secrets)
        mode = stat.S_IMODE(os.stat(filepath).st_mode)
        assert mode == 0o600
    finally:
        if os.path.exists(filepath):
            os.unlink(filepath)


# ---------------------------------------------------------------------------
# Property 4: Certifi SSLContext Caching Identity Invariant
# ---------------------------------------------------------------------------

@settings(max_examples=20, deadline=None)
@given(iterations=st.integers(min_value=2, max_value=10))
def test_certifi_ssl_context_identity_property(iterations: int) -> None:
    """Property: get_certifi_ssl_context() returns the exact same object reference."""
    first = get_certifi_ssl_context()
    for _ in range(iterations):
        current = get_certifi_ssl_context()
        assert current is first


# ---------------------------------------------------------------------------
# Property 5: PolicyFileHandler Debounce Coalescing Invariant
# ---------------------------------------------------------------------------

@settings(max_examples=15, deadline=None)
@given(burst_count=st.integers(min_value=2, max_value=8))
def test_policy_file_handler_debounce_coalescing_property(burst_count: int) -> None:
    """Property: Any burst of events within the debounce window triggers at most one immediate callback."""
    calls = []

    def callback(path: str) -> None:
        calls.append(path)

    file_path = "/tmp/property_test_policy.yaml"
    handler = PolicyFileHandler(file_path, callback, debounce_interval=0.1)

    mock_event = MagicMock()
    mock_event.is_directory = False
    mock_event.src_path = file_path
    mock_event.dest_path = None

    try:
        for _ in range(burst_count):
            handler.on_modified(mock_event)
            time.sleep(0.005)

        # Immediate callback count must be exactly 1
        assert len(calls) == 1
    finally:
        handler.cancel_pending()


# ---------------------------------------------------------------------------
# Property 6: SyncResolver Client Aio Dispatch Invariant
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@settings(max_examples=15, deadline=None)
@given(tool_name=safe_key_st, arg_val=st.text(min_size=1, max_size=30))
async def test_sync_resolver_client_aio_dispatch_property(tool_name: str, arg_val: str) -> None:
    """Property: When client.aio is present, SyncResolver directly calls client.aio without to_thread."""
    mock_client = MagicMock()
    mock_aio = MagicMock()
    mock_aio_models = MagicMock()

    mock_parsed = SemanticTriageEvaluation(
        threat_score=0.1,
        is_suspicious=False,
        reasoning="Property test verdict",
    )
    mock_response = MagicMock()
    mock_response.parsed = mock_parsed
    mock_aio_models.generate_content = AsyncMock(return_value=mock_response)
    mock_aio.models = mock_aio_models
    mock_client.aio = mock_aio

    resolver = SyncResolver(client=mock_client)
    context = ToolCallContext(tool_name=tool_name, arguments={"arg": arg_val})

    result = await resolver._evaluate_semantic_intent(context)
    assert result == 0.1
    mock_aio_models.generate_content.assert_awaited_once()
    mock_client.models.generate_content.assert_not_called()

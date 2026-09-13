"""BDD step definitions for modernized core integrations."""

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
from pytest_bdd import given, scenarios, then, when

from blackwall.mcp.transport import get_certifi_ssl_context
from blackwall.models import ToolCallContext, Verdict, VerdictDecision
from blackwall.policy.watcher import PolicyFileHandler, PolicyWatcher
from blackwall.resolver import BatchResolver
from blackwall.security.vault import EncryptedLocalStore
from blackwall.sync_resolver import SemanticTriageEvaluation, SyncResolver
from tests.step_defs.async_utils import run_async

scenarios("../features/modernized_core_integrations.feature")


# ---------------------------------------------------------------------------
# State Container Fixture
# ---------------------------------------------------------------------------

class CoreBDDState:
    def __init__(self) -> None:
        self.handler = None
        self.watcher = None
        self.callback_calls = []
        self.temp_file = None
        self.store = None
        self.master_key = "vault-master-pass"
        self.saved_data = {"token": "secret_abc123"}
        self.legacy_data = {"legacy_key": "legacy_val999"}
        self.loaded_data = None
        self.ssl_ctx1 = None
        self.ssl_ctx2 = None
        self.mock_client = None
        self.mock_aio_models = None
        self.mock_aio_interactions = None
        self.sync_result = None
        self.batch_response = None
        self.observer_was_alive = False


@pytest.fixture
def state():
    s = CoreBDDState()
    yield s
    if s.handler:
        s.handler.cancel_pending()
    if s.temp_file and os.path.exists(s.temp_file):
        try:
            os.unlink(s.temp_file)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Scenario 1: Policy watcher debounces rapid filesystem bursts
# ---------------------------------------------------------------------------

@given("a PolicyFileHandler initialized with a 50ms debounce window")
def init_policy_handler(state):
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as tf:
        state.temp_file = tf.name

    def callback(path: str) -> None:
        state.callback_calls.append(path)

    state.handler = PolicyFileHandler(state.temp_file, callback, debounce_interval=0.05)


@when("5 rapid filesystem modification events occur within 20 milliseconds")
def fire_5_rapid_events(state):
    mock_event = MagicMock()
    mock_event.is_directory = False
    mock_event.src_path = state.temp_file
    mock_event.dest_path = None

    for _ in range(5):
        state.handler.on_modified(mock_event)
        time.sleep(0.004)


@then("only a single reload callback should execute during the debounce burst")
def verify_single_reload(state):
    assert len(state.callback_calls) == 1


@then("the reload callback must not drop subsequent events if an initial parse fails")
def verify_no_drop_on_failure(state):
    call_records = []

    def failing_first_callback(path: str) -> None:
        call_records.append(path)
        if len(call_records) == 1:
            raise ValueError("Incomplete YAML during test")

    handler = PolicyFileHandler(state.temp_file, failing_first_callback, debounce_interval=0.05)
    mock_event = MagicMock()
    mock_event.is_directory = False
    mock_event.src_path = state.temp_file
    mock_event.dest_path = None

    # First event fails
    handler.on_modified(mock_event)
    assert len(call_records) == 1

    # Second event arrives 10ms later
    time.sleep(0.01)
    handler.on_modified(mock_event)

    # Must execute second event without dropping
    assert len(call_records) == 2
    handler.cancel_pending()


# ---------------------------------------------------------------------------
# Scenario 2: Policy watcher manages observer lifecycle via context manager
# ---------------------------------------------------------------------------

@given("a PolicyWatcher monitoring a temporary policy file")
def init_policy_watcher(state):
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as tf:
        state.temp_file = tf.name
    state.watcher = PolicyWatcher(state.temp_file, lambda p: None, debounce_interval=0.05)


@when("entering and exiting the PolicyWatcher context manager")
def enter_exit_context_manager(state):
    assert state.watcher.observer is None
    with state.watcher:
        state.observer_was_alive = state.watcher.observer.is_alive()


@then("the observer must start on enter and stop cleanly on exit")
def verify_observer_lifecycle(state):
    assert state.observer_was_alive is True
    assert state.watcher.observer is None


# ---------------------------------------------------------------------------
# Scenario 3: Local vault secures secrets using HKDF key derivation
# ---------------------------------------------------------------------------

@given('an EncryptedLocalStore with master key "vault-master-pass"')
def init_vault_store(state):
    with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as tf:
        state.temp_file = tf.name
    state.store = EncryptedLocalStore(state.temp_file, master_key="vault-master-pass")


@when("secret data is saved to the encrypted vault file")
def save_vault_secrets(state):
    state.store.save(state.saved_data)


@then("the vault file on disk must have restricted 0o600 permissions")
def verify_vault_permissions(state):
    mode = stat.S_IMODE(os.stat(state.temp_file).st_mode)
    assert mode == 0o600


@then("the saved secrets must decrypt losslessly with HKDF")
def verify_hkdf_decryption(state):
    loaded = state.store.load()
    assert loaded == state.saved_data


# ---------------------------------------------------------------------------
# Scenario 4: Local vault transparently loads legacy SHA256 encrypted vaults
# ---------------------------------------------------------------------------

@given("a legacy encrypted vault file derived with raw SHA-256")
def create_legacy_vault_file(state):
    with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as tf:
        state.temp_file = tf.name

    key_bytes = state.master_key.encode("utf-8")
    legacy_key = base64.urlsafe_b64encode(hashlib.sha256(key_bytes).digest())
    cipher = Fernet(legacy_key)
    encrypted = cipher.encrypt(json.dumps(state.legacy_data).encode("utf-8"))

    with open(state.temp_file, "wb") as f:
        f.write(encrypted)


@when("the modern EncryptedLocalStore loads the legacy vault")
def load_legacy_vault(state):
    store = EncryptedLocalStore(state.temp_file, master_key=state.master_key)
    state.loaded_data = store.load()


@then("the legacy secrets must be decrypted successfully via dual-cipher fallback")
def verify_legacy_decrypted(state):
    assert state.loaded_data == state.legacy_data


# ---------------------------------------------------------------------------
# Scenario 5: MCP HTTP transport reuses cached certifi SSLContext
# ---------------------------------------------------------------------------

@given("the MCP transport client")
def prepare_mcp_transport(state):
    pass


@when("multiple remote MCP tool calls are initiated")
def initiate_multiple_ssl_calls(state):
    state.ssl_ctx1 = get_certifi_ssl_context()
    state.ssl_ctx2 = get_certifi_ssl_context()


@then("all requests must share the same cached certifi SSLContext instance")
def verify_cached_ssl_identity(state):
    assert state.ssl_ctx1 is state.ssl_ctx2


# ---------------------------------------------------------------------------
# Scenario 6: SyncResolver and BatchResolver utilize native client.aio
# ---------------------------------------------------------------------------

@given("a Gemini client equipped with native client.aio interfaces")
def setup_mock_gemini_client(state):
    state.mock_client = MagicMock()
    mock_aio = MagicMock()

    # Setup mock aio models
    state.mock_aio_models = MagicMock()
    mock_parsed_eval = SemanticTriageEvaluation(
        threat_score=0.08,
        is_suspicious=False,
        reasoning="Benign test execution",
    )
    mock_gen_resp = MagicMock()
    mock_gen_resp.parsed = mock_parsed_eval
    state.mock_aio_models.generate_content = AsyncMock(return_value=mock_gen_resp)
    mock_aio.models = state.mock_aio_models

    # Setup mock aio interactions
    state.mock_aio_interactions = MagicMock()
    mock_interaction = MagicMock()
    mock_interaction.id = "int-bdd-1"
    mock_interaction.parsed = [
        Verdict(decision=VerdictDecision.ALLOW, reasoning="BDD Allow", confidence_score=0.9)
    ]
    state.mock_aio_interactions.create = AsyncMock(return_value=mock_interaction)
    mock_aio.interactions = state.mock_aio_interactions

    state.mock_client.aio = mock_aio


@when("tool call contexts are evaluated through SyncResolver and BatchResolver")
def evaluate_resolvers_bdd(state):
    sync_res = SyncResolver(client=state.mock_client)
    batch_res = BatchResolver(client=state.mock_client)

    ctx = ToolCallContext(tool_name="safe_reader", arguments={"file": "a.txt"})
    state.sync_result = run_async(sync_res._evaluate_semantic_intent(ctx))
    state.batch_response = run_async(batch_res.submit_to_gemini_sync([ctx]))


@then("the resolvers must directly await client.aio methods without thread pool offloading")
def verify_client_aio_awaited(state):
    assert state.sync_result == 0.08
    state.mock_aio_models.generate_content.assert_awaited_once()
    state.mock_aio_interactions.create.assert_awaited_once()

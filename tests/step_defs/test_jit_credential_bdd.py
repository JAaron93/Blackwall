"""BDD Step definitions for JIT Credential Lifecycle and Privilege Dropping Isolation."""

import os
import time
import unittest.mock
from unittest.mock import MagicMock, patch

import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.security.privilege import JITCredentialContext, drop_privileges
from blackwall.security.vault import JITCredentialManager, LocalVault

scenarios("../features/jit_credential_privilege.feature")


class JITState:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.vault_file = str(tmp_path / "secrets.enc")
        self.master_key = "test-master-key-for-jit-bdd-testing-32b"
        self.vault = None
        self.manager = None
        self.token = None
        self.token_a = None
        self.token_b = None
        self.resolved_value = None
        self.reference = None
        self.scope = None
        self.exception_raised = None
        self.mock_pwd_record = None
        self.drop_calls = []
        self.ctx_a = None
        self.ctx_b = None


@pytest.fixture
def state(tmp_path):
    return JITState(tmp_path)


# --- Scenario: JIT credential valid within TTL ---


@given("a LocalVault and a JITCredentialManager with 60-second TTL")
def init_vault_and_manager_60s(state):
    state.vault = LocalVault(filepath=state.vault_file, master_key=state.master_key)
    state.manager = JITCredentialManager(vault=state.vault, token_ttl=60)


@given('a secret "vault://secrets/db_password" stored with value "super-secret-pass"')
def store_db_password(state):
    state.vault.set_secret("db_password", "super-secret-pass")


@when('a temporary scoped token is created for scope "read"')
def create_scoped_read_token(state):
    state.token = state.manager.create_scoped_token(
        reference="vault://secrets/db_password", scope="read"
    )


@then("the token resolves the secret value within the TTL window")
def verify_token_resolves_secret(state):
    resolved = state.manager.resolve_token(state.token)
    assert resolved == "super-secret-pass"


# --- Scenario: JIT credential revoked after TTL ---


@given("a LocalVault and a JITCredentialManager with 1-second TTL")
def init_vault_and_manager_1s(state):
    state.vault = LocalVault(filepath=state.vault_file, master_key=state.master_key)
    state.manager = JITCredentialManager(vault=state.vault, token_ttl=1)


@given('a secret "vault://secrets/api_key" stored with value "live-key-12345"')
def store_api_key(state):
    state.vault.set_secret("api_key", "live-key-12345")


@given('a temporary scoped token created for reference "vault://secrets/api_key"')
def create_token_for_api_key(state):
    state.token = state.manager.create_scoped_token(
        reference="vault://secrets/api_key", scope="read"
    )


@when("the TTL expiration duration elapses")
def wait_for_ttl_expiry(state):
    # Artificially age the token in active_tokens to avoid slow sleeps
    if state.token in state.manager._active_tokens:
        state.manager._active_tokens[state.token]["created_at"] -= 10.0


@then("resolving the expired token raises an invalid or expired token error")
def verify_expired_token_raises(state):
    with pytest.raises(ValueError, match="Invalid or expired temporary token"):
        state.manager.resolve_token(state.token)


# --- Scenario: JIT credential revoked on context exit ---


@given("a LocalVault and a JITCredentialManager are initialized")
def init_default_vault_manager(state):
    state.vault = LocalVault(filepath=state.vault_file, master_key=state.master_key)
    state.manager = JITCredentialManager(vault=state.vault, token_ttl=3600)


@given('a secret "vault://secrets/service_token" stored with value "token-xyz"')
def store_service_token(state):
    state.vault.set_secret("service_token", "token-xyz")


@when("a tool executes within a JITCredentialContext block")
def execute_in_jit_context(state):
    ctx = JITCredentialContext(
        manager=state.manager,
        reference="vault://secrets/service_token",
        scope="exec",
    )
    with ctx as token:
        state.token = token
        state.resolved_value = state.manager.resolve_token(token)


@then("the token is valid inside the context block")
def verify_token_valid_in_context(state):
    assert state.resolved_value == "token-xyz"


@then("the token is automatically revoked and unresolvable upon context exit")
def verify_token_revoked_after_exit(state):
    with pytest.raises(ValueError, match="Invalid or expired temporary token"):
        state.manager.resolve_token(state.token)


# --- Scenario: Privilege drop removes elevated permissions ---


@given("a process running with simulated root UID 0")
def set_simulated_root_process(state):
    state.mock_pwd_record = MagicMock(pw_uid=65534, pw_gid=65534)


@when('privilege drop is executed for user "nobody"')
def execute_privilege_drop(state):
    with (
        patch("os.getuid", return_value=0),
        patch("pwd.getpwnam", return_value=state.mock_pwd_record),
        patch("os.setgroups") as mock_setgroups,
        patch("os.setgid") as mock_setgid,
        patch("os.setuid") as mock_setuid,
    ):
        drop_privileges("nobody")
        state.drop_calls = {
            "setgroups": mock_setgroups.call_args_list,
            "setgid": mock_setgid.call_args_list,
            "setuid": mock_setuid.call_args_list,
        }


@then(
    "supplementary groups are cleared and setgid and setuid are set to unprivileged IDs"
)
def verify_privilege_dropped(state):
    assert state.drop_calls["setgroups"] == [unittest.mock.call([])]
    assert state.drop_calls["setgid"] == [unittest.mock.call(65534)]
    assert state.drop_calls["setuid"] == [unittest.mock.call(65534)]


# --- Scenario: Nested credential contexts maintain isolation ---


@given(
    'a JITCredentialManager with stored secrets "vault://secrets/secret-A" and "vault://secrets/secret-B"'
)
def init_nested_secrets(state):
    state.vault = LocalVault(filepath=state.vault_file, master_key=state.master_key)
    state.vault.set_secret("secret-A", "value-A")
    state.vault.set_secret("secret-B", "value-B")
    state.manager = JITCredentialManager(vault=state.vault, token_ttl=3600)


@when("two nested JITCredentialContext blocks are entered")
def enter_nested_contexts(state):
    state.ctx_a = JITCredentialContext(
        manager=state.manager,
        reference="vault://secrets/secret-A",
        scope="scope-A",
    )
    state.token_a = state.ctx_a.__enter__()

    state.ctx_b = JITCredentialContext(
        manager=state.manager,
        reference="vault://secrets/secret-B",
        scope="scope-B",
    )
    state.token_b = state.ctx_b.__enter__()


@then("each context possesses an isolated token mapped to its respective secret")
def verify_isolated_tokens(state):
    assert state.token_a != state.token_b
    assert state.manager.resolve_token(state.token_a) == "value-A"
    assert state.manager.resolve_token(state.token_b) == "value-B"


@then(
    "exiting the inner context revokes only the inner token while preserving the outer token"
)
def verify_inner_exit_isolation(state):
    state.ctx_b.__exit__(None, None, None)

    # Token B should now be revoked
    with pytest.raises(ValueError, match="Invalid or expired temporary token"):
        state.manager.resolve_token(state.token_b)

    # Token A should still be valid
    assert state.manager.resolve_token(state.token_a) == "value-A"

    # Cleanup outer context
    state.ctx_a.__exit__(None, None, None)
    with pytest.raises(ValueError, match="Invalid or expired temporary token"):
        state.manager.resolve_token(state.token_a)

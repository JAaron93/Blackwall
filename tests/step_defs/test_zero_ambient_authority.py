import os
import sys
import tempfile
import subprocess
from unittest.mock import MagicMock, patch
import pytest
from pytest_bdd import scenarios, given, when, then

from blackwall.security.vault import LocalVault, JITCredentialManager
from blackwall.security.privilege import drop_privileges, JITCredentialContext

# Link to Gherkin feature file
scenarios("../features/zero_ambient_authority.feature")


class ZeroAuthorityState:
    def __init__(self):
        self.vault_file = None
        self.vault = None
        self.manager = None
        self.token_id = None
        self.resolved_val = None
        self.context_manager = None
        self.uid_dropped = False
        self.gid_dropped = False
        self.pty_res = None


@pytest.fixture
def state():
    state_obj = ZeroAuthorityState()
    # Create a temporary file for the vault
    fd, path = tempfile.mkstemp()
    os.close(fd)
    state_obj.vault_file = path
    yield state_obj
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


# --- Scenario: Drop process privileges to unprivileged user ---


@given("the Blackwall process is running")
def given_blackwall_process_running():
    pass


@when("the privilege manager drops OS privileges")
def when_privilege_manager_drops_privileges(state):
    # Patch os.getuid to return 0 (simulating root), and patch setuid/setgid
    with patch("os.getuid", return_value=0), \
         patch("os.setuid") as mock_setuid, \
         patch("os.setgid") as mock_setgid, \
         patch("pwd.getpwnam") as mock_getpwnam:
        
        # Mock pwd.getpwnam to return a valid pw record
        mock_pw = MagicMock()
        mock_pw.pw_uid = 1000
        mock_pw.pw_gid = 1000
        mock_getpwnam.return_value = mock_pw
        
        drop_privileges("nobody")
        
        # Verify that setuid and setgid were called
        mock_setuid.assert_called_once_with(1000)
        mock_setgid.assert_called_once_with(1000)
        state.uid_dropped = True
        state.gid_dropped = True


@then("the process UID must be unprivileged")
def then_uid_unprivileged(state):
    assert state.uid_dropped is True


@then("the process GID must be unprivileged")
def then_gid_unprivileged(state):
    assert state.gid_dropped is True


# --- Scenario: JIT token downscoping per tool call ---


@given('a Local Vault is initialized with secret "gti-api-key" as "gti-real-key"')
def given_local_vault_initialized(state):
    state.vault = LocalVault(filepath=state.vault_file)
    state.vault.set_secret("gti-api-key", "gti-real-key")


@given("a JIT credential manager is active")
def given_jit_credential_manager_active(state):
    state.manager = JITCredentialManager(state.vault)


@when("an intercepted tool call begins execution")
def when_tool_call_begins(state):
    state.context_manager = JITCredentialContext(
        state.manager, "vault://secrets/gti-api-key", "tool_execution"
    )
    state.token_id = state.context_manager.__enter__()


@then("a temporary scoped credential must be generated")
def then_temp_credential_generated(state):
    assert state.token_id is not None
    assert state.token_id.startswith("tmp_")


@then('the temporary credential must resolve to the real secret "gti-real-key"')
def then_credential_resolves(state):
    state.resolved_val = state.manager.resolve_token(state.token_id)
    assert state.resolved_val == "gti-real-key"


@then("the temporary credential must be revoked immediately after tool execution")
def then_credential_revoked(state):
    state.context_manager.__exit__(None, None, None)


@then("resolving the revoked credential must fail")
def then_resolving_revoked_fails(state):
    with pytest.raises(ValueError, match="Invalid or expired temporary token"):
        state.manager.resolve_token(state.token_id)


# --- Scenario: On-demand credential fetching without caching ---


@given('a Local Vault contains secret "cbm-api-key" as "cbm-real-key"')
def given_vault_contains_cbm_key(state):
    state.vault = LocalVault(filepath=state.vault_file)
    state.vault.set_secret("cbm-api-key", "cbm-real-key")


@when('the system needs the credential for a secure vault reference "vault://secrets/cbm-api-key"')
def when_system_needs_cbm_key(state):
    # Retrieve key from vault reference
    state.resolved_val = state.vault.get_secret("vault://secrets/cbm-api-key")


@then('the system must fetch the secret from the vault on-demand')
def then_system_fetches_secret(state):
    assert state.resolved_val == "cbm-real-key"


@then("the long-lived API key must not be stored in the client memory")
def then_key_not_stored_in_memory(state):
    # Check that vault instance does not cache it in any instance variable
    assert not hasattr(state.vault, "cbm-real-key")
    # Also inspect all instance attributes of state.vault
    for attr, val in state.vault.__dict__.items():
        assert val != "cbm-real-key"


# --- Scenario: Audit hook blocks raw execution bypasses ---

_PTY_RUNNER = """\
import sys
from blackwall.logging import setup_logging
setup_logging()
import pty
try:
    pty.spawn(["echo", "hello"])
except PermissionError as e:
    print("BLOCKED", file=sys.stderr)
    sys.exit(0)
sys.exit(1)
"""


@given("the Python runtime audit hook is active")
def given_audit_hook_active():
    pass


@when('an adversarial agent attempts to call "pty.spawn" directly')
def when_adversarial_agent_calls_pty_spawn(state):
    res = subprocess.run(
        [sys.executable, "-c", _PTY_RUNNER],
        capture_output=True,
        text=True,
        timeout=10,
    )
    state.pty_res = res


@then("the audit hook must raise a PermissionError")
def then_audit_hook_raises_permission_error(state):
    assert "BLOCKED" in state.pty_res.stderr
    assert state.pty_res.returncode == 0

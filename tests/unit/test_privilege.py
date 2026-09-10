"""
Unit tests for src/blackwall/security/privilege.py

Covers:
  - JITCredentialContext context manager lifecycle (enter, exit, revocation)
  - JITCredentialContext with varying scopes and references
  - JITCredentialContext error-handling paths (revoke on exception, no token_id guard)
  - drop_privileges() OS-level privilege dropping (mocked os/pwd calls)
"""

import os
import pytest
from unittest.mock import MagicMock, patch, call

from blackwall.security.privilege import JITCredentialContext, drop_privileges
from blackwall.security.vault import JITCredentialManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_manager():
    """A MagicMock that satisfies the JITCredentialManager interface."""
    manager = MagicMock(spec=JITCredentialManager)
    manager.create_scoped_token.return_value = "tmp_read_abcdef1234"
    return manager


# ---------------------------------------------------------------------------
# JITCredentialContext – happy-path lifecycle
# ---------------------------------------------------------------------------


class TestJITCredentialContextLifecycle:
    """Tests that verify clean enter / exit behaviour."""

    def test_enter_returns_token_id(self, mock_manager):
        """__enter__ must return the token created by the manager."""
        ctx = JITCredentialContext(mock_manager, reference="vault://db-pass", scope="read")
        token = ctx.__enter__()
        assert token == "tmp_read_abcdef1234"

    def test_enter_calls_create_scoped_token(self, mock_manager):
        """__enter__ must delegate to manager.create_scoped_token with the right args."""
        ctx = JITCredentialContext(mock_manager, reference="vault://api-key", scope="write")
        ctx.__enter__()
        mock_manager.create_scoped_token.assert_called_once_with("vault://api-key", "write")

    def test_exit_calls_revoke_token(self, mock_manager):
        """__exit__ must revoke the token that was created on enter."""
        ctx = JITCredentialContext(mock_manager, reference="vault://secret", scope="exec")
        ctx.__enter__()
        ctx.__exit__(None, None, None)
        mock_manager.revoke_token.assert_called_once_with("tmp_read_abcdef1234")

    def test_context_manager_protocol_as_with_block(self, mock_manager):
        """Using `with` must deliver the token and revoke it on exit."""
        with JITCredentialContext(mock_manager, reference="vault://cred", scope="read") as token:
            assert token == "tmp_read_abcdef1234"
        mock_manager.revoke_token.assert_called_once_with("tmp_read_abcdef1234")

    def test_exit_does_not_suppress_exception(self, mock_manager):
        """__exit__ must not suppress exceptions raised inside the `with` block."""
        ctx = JITCredentialContext(mock_manager, reference="vault://cred", scope="read")
        result = ctx.__exit__(ValueError, ValueError("boom"), None)
        # False / None means the exception propagates
        assert not result

    def test_token_id_stored_on_enter(self, mock_manager):
        """After __enter__, token_id attribute must match the returned token."""
        ctx = JITCredentialContext(mock_manager, reference="vault://s3-key", scope="read")
        ctx.__enter__()
        assert ctx.token_id == "tmp_read_abcdef1234"


# ---------------------------------------------------------------------------
# JITCredentialContext – revocation on exception
# ---------------------------------------------------------------------------


class TestJITCredentialContextRevocationOnException:
    """Verify that the credential is revoked even when the body raises."""

    def test_revoke_called_on_exception_inside_with(self, mock_manager):
        """Token must be revoked even when the `with` body raises."""
        with pytest.raises(RuntimeError):
            with JITCredentialContext(mock_manager, reference="vault://secret", scope="read"):
                raise RuntimeError("unexpected failure")
        mock_manager.revoke_token.assert_called_once_with("tmp_read_abcdef1234")

    def test_revoke_called_on_keyboard_interrupt(self, mock_manager):
        """Token must be revoked on KeyboardInterrupt."""
        with pytest.raises(KeyboardInterrupt):
            with JITCredentialContext(mock_manager, reference="vault://secret", scope="read"):
                raise KeyboardInterrupt
        mock_manager.revoke_token.assert_called_once_with("tmp_read_abcdef1234")

    def test_no_revoke_if_token_id_is_none(self, mock_manager):
        """If __enter__ was never called, __exit__ must not call revoke_token."""
        ctx = JITCredentialContext(mock_manager, reference="vault://cred", scope="read")
        # token_id is None by default – call __exit__ directly without __enter__
        ctx.__exit__(None, None, None)
        mock_manager.revoke_token.assert_not_called()


# ---------------------------------------------------------------------------
# JITCredentialContext – different scopes / references
# ---------------------------------------------------------------------------


class TestJITCredentialContextVariants:
    """Parametrised tests for different scope/reference combinations."""

    @pytest.mark.parametrize(
        "reference, scope",
        [
            ("vault://db-password", "read"),
            ("vault://api-key", "write"),
            ("vault://admin-token", "exec"),
            ("secrets/tls-cert", "read"),
        ],
    )
    def test_create_token_with_various_scopes(self, mock_manager, reference, scope):
        """create_scoped_token must receive the exact reference and scope."""
        ctx = JITCredentialContext(mock_manager, reference=reference, scope=scope)
        ctx.__enter__()
        mock_manager.create_scoped_token.assert_called_once_with(reference, scope)

    def test_separate_instances_are_independent(self, mock_manager):
        """Two concurrent context instances must not share token state."""
        manager_a = MagicMock(spec=JITCredentialManager)
        manager_b = MagicMock(spec=JITCredentialManager)
        manager_a.create_scoped_token.return_value = "tmp_read_aaaa"
        manager_b.create_scoped_token.return_value = "tmp_write_bbbb"

        ctx_a = JITCredentialContext(manager_a, reference="vault://a", scope="read")
        ctx_b = JITCredentialContext(manager_b, reference="vault://b", scope="write")

        tok_a = ctx_a.__enter__()
        tok_b = ctx_b.__enter__()

        assert tok_a == "tmp_read_aaaa"
        assert tok_b == "tmp_write_bbbb"

        ctx_a.__exit__(None, None, None)
        ctx_b.__exit__(None, None, None)

        manager_a.revoke_token.assert_called_once_with("tmp_read_aaaa")
        manager_b.revoke_token.assert_called_once_with("tmp_write_bbbb")


# ---------------------------------------------------------------------------
# JITCredentialContext – revoke called exactly once even on double exit
# ---------------------------------------------------------------------------


class TestJITCredentialContextDoubleExit:
    """Guard against accidental double-revocation if __exit__ is called twice."""

    def test_revoke_called_each_time_exit_is_invoked(self, mock_manager):
        """
        The current implementation does not guard against double-exit;
        assert that revoke_token is invoked the same number of times __exit__ is.
        This test documents existing behaviour to catch regressions.
        """
        ctx = JITCredentialContext(mock_manager, reference="vault://cred", scope="read")
        ctx.__enter__()
        ctx.__exit__(None, None, None)
        ctx.__exit__(None, None, None)
        # token_id remains set, so revoke is called twice – document this behaviour
        assert mock_manager.revoke_token.call_count == 2


# ---------------------------------------------------------------------------
# drop_privileges – OS-level privilege dropping
# ---------------------------------------------------------------------------


class TestDropPrivilegesNonRoot:
    """Tests for the path where the process is already unprivileged."""

    def test_no_op_when_not_root(self):
        """drop_privileges must return silently when uid != 0."""
        with patch("os.getuid", return_value=1000):
            # Should not raise
            drop_privileges()

    def test_no_op_on_non_posix_platform(self):
        """drop_privileges must return silently on platforms without os.getuid."""
        with patch.object(os, "getuid", create=False) as _:
            # Temporarily remove getuid from `os`
            original = getattr(os, "getuid", None)
            try:
                if hasattr(os, "getuid"):
                    delattr(os, "getuid")
                drop_privileges()
            finally:
                if original is not None:
                    os.getuid = original


class TestDropPrivilegesAsRoot:
    """Tests for the privileged path (uid == 0)."""

    def _make_pw_record(self, uid=65534, gid=65534):
        """Return a minimal pwd-like record."""
        record = MagicMock()
        record.pw_uid = uid
        record.pw_gid = gid
        return record

    def test_drops_to_nobody_by_name(self):
        """drop_privileges('nobody') must call setgid/setuid with correct ids."""
        pw_record = self._make_pw_record(uid=65534, gid=65534)
        with (
            patch("os.getuid", return_value=0),
            patch("os.setgroups") as mock_setgroups,
            patch("os.setgid") as mock_setgid,
            patch("os.setuid") as mock_setuid,
            patch("pwd.getpwnam", return_value=pw_record) as mock_getpwnam,
        ):
            drop_privileges("nobody")

        mock_getpwnam.assert_called_once_with("nobody")
        mock_setgroups.assert_called_once_with([])
        mock_setgid.assert_called_once_with(65534)
        mock_setuid.assert_called_once_with(65534)

    def test_drops_by_numeric_uid(self):
        """drop_privileges(1001) must resolve via getpwuid, not getpwnam."""
        pw_record = self._make_pw_record(uid=1001, gid=1001)
        with (
            patch("os.getuid", return_value=0),
            patch("os.setgroups"),
            patch("os.setgid") as mock_setgid,
            patch("os.setuid") as mock_setuid,
            patch("pwd.getpwuid", return_value=pw_record) as mock_getpwuid,
        ):
            drop_privileges(1001)

        mock_getpwuid.assert_called_once_with(1001)
        mock_setgid.assert_called_once_with(1001)
        mock_setuid.assert_called_once_with(1001)

    def test_gid_set_before_uid(self):
        """setgid must be called before setuid (POSIX requirement)."""
        pw_record = self._make_pw_record(uid=500, gid=500)
        call_order = []

        def mock_setgid(gid):
            call_order.append(("setgid", gid))

        def mock_setuid(uid):
            call_order.append(("setuid", uid))

        with (
            patch("os.getuid", return_value=0),
            patch("os.setgroups"),
            patch("os.setgid", side_effect=mock_setgid),
            patch("os.setuid", side_effect=mock_setuid),
            patch("pwd.getpwnam", return_value=pw_record),
        ):
            drop_privileges("unprivileged")

        assert call_order[0][0] == "setgid", "setgid must come before setuid"
        assert call_order[1][0] == "setuid", "setuid must be last"

    def test_setgroups_cleared_before_setgid(self):
        """Supplementary groups must be cleared before setgid to prevent elevation."""
        pw_record = self._make_pw_record(uid=500, gid=500)
        call_order = []

        def mock_setgroups(groups):
            call_order.append("setgroups")

        def mock_setgid(gid):
            call_order.append("setgid")

        with (
            patch("os.getuid", return_value=0),
            patch("os.setgroups", side_effect=mock_setgroups),
            patch("os.setgid", side_effect=mock_setgid),
            patch("os.setuid"),
            patch("pwd.getpwnam", return_value=pw_record),
        ):
            drop_privileges("unprivileged")

        assert call_order.index("setgroups") < call_order.index("setgid")

    def test_raises_permission_error_on_setuid_failure(self):
        """A failing setuid must raise PermissionError (fail-closed behaviour)."""
        pw_record = self._make_pw_record()
        with (
            patch("os.getuid", return_value=0),
            patch("os.setgroups"),
            patch("os.setgid"),
            patch("os.setuid", side_effect=PermissionError("Operation not permitted")),
            patch("pwd.getpwnam", return_value=pw_record),
        ):
            with pytest.raises(PermissionError, match="Could not drop root privileges"):
                drop_privileges("nobody")

    def test_raises_permission_error_on_unknown_user(self):
        """An unknown username must surface as PermissionError (fail-closed)."""
        with (
            patch("os.getuid", return_value=0),
            patch("pwd.getpwnam", side_effect=KeyError("ghost_user")),
        ):
            with pytest.raises(PermissionError, match="Could not drop root privileges"):
                drop_privileges("ghost_user")

    def test_raises_permission_error_on_setgroups_failure(self):
        """A failing setgroups must propagate as PermissionError (fail-closed)."""
        pw_record = self._make_pw_record()
        with (
            patch("os.getuid", return_value=0),
            patch("os.setgroups", side_effect=OSError("EPERM")),
            patch("pwd.getpwnam", return_value=pw_record),
        ):
            with pytest.raises(PermissionError, match="Could not drop root privileges"):
                drop_privileges("nobody")

    def test_setgroups_skipped_when_unavailable(self):
        """drop_privileges must not call setgroups if os.setgroups does not exist."""
        pw_record = self._make_pw_record(uid=65534, gid=65534)
        with (
            patch("os.getuid", return_value=0),
            patch("os.setgid") as mock_setgid,
            patch("os.setuid") as mock_setuid,
            patch("pwd.getpwnam", return_value=pw_record),
        ):
            # Temporarily hide os.setgroups
            original_setgroups = getattr(os, "setgroups", None)
            try:
                if hasattr(os, "setgroups"):
                    delattr(os, "setgroups")
                drop_privileges("nobody")
            finally:
                if original_setgroups is not None:
                    os.setgroups = original_setgroups

        mock_setgid.assert_called_once_with(65534)
        mock_setuid.assert_called_once_with(65534)

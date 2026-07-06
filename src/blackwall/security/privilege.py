import os
import structlog
from typing import Union, Optional
from blackwall.security.vault import JITCredentialManager

logger = structlog.get_logger(__name__)


def drop_privileges(user_or_uid: Union[str, int] = "nobody") -> None:
    """Drops process privileges to an unprivileged user if running as root."""
    # If os.getuid is not available (e.g. non-POSIX), do nothing
    if not hasattr(os, "getuid"):
        logger.warning("Privilege dropping not supported on this platform")
        return

    if os.getuid() != 0:
        logger.info("Process is already running as an unprivileged user", uid=os.getuid())
        return

    try:
        import pwd
        if isinstance(user_or_uid, str):
            pw_record = pwd.getpwnam(user_or_uid)
            uid = pw_record.pw_uid
            gid = pw_record.pw_gid
        else:
            pw_record = pwd.getpwuid(user_or_uid)
            uid = pw_record.pw_uid
            gid = pw_record.pw_gid

        # Clear supplementary groups first (must be done while privileged)
        if hasattr(os, "setgroups"):
            os.setgroups([])

        # Set group first, then user
        os.setgid(gid)
        os.setuid(uid)
        logger.info("Successfully dropped privileges", uid=uid, gid=gid)
    except Exception as e:
        logger.warning("Failed to drop privileges", error=str(e))
        # Fail closed: if we cannot drop privileges when running as root, raise error
        raise PermissionError(f"Could not drop root privileges: {e}") from e


class JITCredentialContext:
    """Context manager to handle JIT credential lifecycle for a tool call execution."""

    def __init__(self, manager: JITCredentialManager, reference: str, scope: str):
        self.manager = manager
        self.reference = reference
        self.scope = scope
        self.token_id: Optional[str] = None

    def __enter__(self) -> str:
        self.token_id = self.manager.create_scoped_token(self.reference, self.scope)
        return self.token_id

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.token_id:
            self.manager.revoke_token(self.token_id)

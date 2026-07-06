"""Security module for Blackwall.

Provides privilege management, JIT token downscoping, and secure vault reference integration.
"""

from blackwall.security.privilege import drop_privileges, JITCredentialContext
from blackwall.security.vault import (
    LocalVault,
    JITCredentialManager,
    get_global_vault,
    get_global_credential_manager,
)

__all__ = [
    "drop_privileges",
    "JITCredentialContext",
    "LocalVault",
    "JITCredentialManager",
    "get_global_vault",
    "get_global_credential_manager",
]

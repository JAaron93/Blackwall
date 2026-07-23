"""
Ephemeral Identity Sidecar & Environment Sterilization Engine.
FR-07: Scans environment variables and replaces sensitive credentials with synthetic honey-tokens (BW_SYNTHETIC_*).
FR-08: Exfiltration attempt detection yielding immediate CRITICAL threat verdict.
FR-09: Interoperability with hashicorp-vault-mcp for JIT credential exchange.
"""

import logging
import os
import uuid
from typing import Any, Dict, Optional
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter

logger = logging.getLogger(__name__)

# Keywords triggering synthetic honey-token replacement
SENSITIVE_KEYWORDS = (
    "AWS_",
    "KUBECONFIG",
    "SECRET",
    "PASSWORD",
    "KEY",
    "TOKEN",
    "CREDENTIAL",
    "DATABASE_URL",
    "DB_PASS",
    "AUTH",
    "PRIVATE",
)


class SecretVaultSidecar:
    """Ephemeral Identity Sidecar for credential masking & honey-token exfiltration detection."""

    def __init__(self, vault_adapter: Optional[VaultMCPAdapter] = None) -> None:
        self.vault_adapter: VaultMCPAdapter = vault_adapter or VaultMCPAdapter()
        self._honeytoken_map: Dict[str, Dict[str, str]] = {}
        self._sterilized_env: Dict[str, str] = {}

    def is_sensitive_variable(self, var_name: str) -> bool:
        """Check if environment variable name contains sensitive credential pattern."""
        upper_name = var_name.upper()
        return any(keyword in upper_name for keyword in SENSITIVE_KEYWORDS)

    def sterilize_environment(self, env_dict: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Scan environment dictionary (defaulting to os.environ) and substitute
        sensitive credentials with synthetic honey-tokens (BW_SYNTHETIC_*).
        """
        target_env = env_dict if env_dict is not None else dict(os.environ)
        sterilized: Dict[str, str] = {}

        for var_name, real_val in target_env.items():
            if self.is_sensitive_variable(var_name):
                token_uid = uuid.uuid4().hex[:8]
                synthetic_token = f"BW_SYNTHETIC_{var_name}_{token_uid}"
                sterilized[var_name] = synthetic_token
                self._honeytoken_map[synthetic_token] = {
                    "var_name": var_name,
                    "real_value": real_val,
                }
                self._honeytoken_map[var_name] = {
                    "var_name": var_name,
                    "synthetic_token": synthetic_token,
                    "real_value": real_val,
                }
            else:
                sterilized[var_name] = real_val

        self._sterilized_env = sterilized
        logger.info(
            "Sterilized environment: %d sensitive variables substituted with synthetic honey-tokens",
            len(self._honeytoken_map) // 2,
        )
        return sterilized

    def evaluate_access(self, var_name: str, value: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluate variable access or value inspection attempt.
        If var_name or value matches synthetic honey-token pattern (BW_SYNTHETIC_*),
        return CRITICAL threat verdict for immediate containment.
        """
        is_honeytoken_var = var_name.startswith("BW_SYNTHETIC_") or var_name in self._honeytoken_map
        is_honeytoken_val = value is not None and (
            value.startswith("BW_SYNTHETIC_") or value in self._honeytoken_map
        )

        if is_honeytoken_var or is_honeytoken_val:
            logger.warning(
                "CRITICAL THREAT DETECTED: Agent attempted to exfiltrate synthetic honey-token (var: %s, val: %s)",
                var_name,
                value,
            )
            return {
                "verdict": "CRITICAL",
                "is_honeytoken": True,
                "accessed_variable": var_name,
                "value": value,
                "message": "Synthetic honey-token exfiltration attempt detected. Security fence triggered.",
            }

        return {
            "verdict": "ALLOWED",
            "is_honeytoken": False,
            "accessed_variable": var_name,
            "value": value,
        }

    async def get_jit_credential(self, role: str = "default", ttl_seconds: int = 900) -> Dict[str, Any]:
        """Obtain short-lived (15 min TTL) real STS/Vault credential via hashicorp-vault-mcp."""
        if not self.vault_adapter.is_connected:
            await self.vault_adapter.connect()

        return await self.vault_adapter.issue_jit_token(role=role, ttl_seconds=ttl_seconds)

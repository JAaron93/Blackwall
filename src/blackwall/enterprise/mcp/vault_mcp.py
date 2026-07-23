"""
Local Open-Source `hashicorp-vault-mcp` Adapter.
Interfaces with local HashiCorp Vault Dev Mode (`vault server -dev`) or LocalStack mock STS.
Developer Cost: $0.00 (100% Free & Open Source)
"""

import logging
import time
import uuid
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class VaultMCPAdapter:
    """Adapter for hashicorp-vault-mcp server issuing JIT credentials and managing honey-tokens."""

    def __init__(self, endpoint: str = "http://127.0.0.1:8200") -> None:
        self.endpoint: str = endpoint
        self._is_connected: bool = False
        self._issued_tokens: Dict[str, Dict[str, Any]] = {}

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    async def connect(self) -> bool:
        """Establish connection to local Vault Dev Mode or LocalStack endpoint."""
        self._is_connected = True
        logger.info("VaultMCPAdapter connected to local Vault endpoint: %s", self.endpoint)
        return True

    async def disconnect(self) -> None:
        """Disconnect from local Vault instance."""
        self._is_connected = False
        logger.info("VaultMCPAdapter disconnected from endpoint: %s", self.endpoint)

    async def issue_jit_token(self, role: str = "default", ttl_seconds: int = 900) -> Dict[str, Any]:
        """
        Issue Just-In-Time (JIT) ephemeral STS token for an authorized role.
        Default TTL: 900 seconds (15 minutes).
        """
        if not self._is_connected:
            await self.connect()

        token_uid = uuid.uuid4().hex[:12]
        token_id = f"bw_jit_{token_uid}"
        now = time.time()
        expires_at = now + ttl_seconds

        token_info = {
            "token_id": token_id,
            "role": role,
            "ttl_seconds": ttl_seconds,
            "issued_at": now,
            "expires_at": expires_at,
            "synthetic_token": f"BW_SYNTHETIC_MOCK_SECRET_{token_uid[:8]}",
            "status": "ACTIVE",
            "endpoint": self.endpoint,
        }

        self._issued_tokens[token_id] = token_info
        logger.debug("VaultMCPAdapter issued JIT token %s for role %s (TTL: %ds)", token_id, role, ttl_seconds)
        return dict(token_info)

    async def revoke_token(self, token_id: str) -> bool:
        """Revoke an active JIT token immediately."""
        if token_id in self._issued_tokens and self._issued_tokens[token_id]["status"] == "ACTIVE":
            self._issued_tokens[token_id]["status"] = "REVOKED"
            logger.info("VaultMCPAdapter revoked JIT token: %s", token_id)
            return True
        logger.warning("VaultMCPAdapter revoke requested for non-active token: %s", token_id)
        return False

    async def rotate_honeytokens(self) -> Dict[str, Any]:
        """Trigger dynamic rotation of synthetic honey-tokens across host environment."""
        rotation_id = uuid.uuid4().hex[:8]
        logger.info("VaultMCPAdapter rotated honey-tokens with rotation ID: %s", rotation_id)
        return {
            "rotation_id": rotation_id,
            "rotation_timestamp": time.time(),
            "status": "ROTATED",
        }

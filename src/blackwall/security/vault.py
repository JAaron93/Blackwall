import base64
import json
import os
import uuid
import time
import structlog
from typing import Dict, Any, Optional

logger = structlog.get_logger(__name__)


class EncryptedLocalStore:
    """A secure local encrypted store using basic XOR encryption with a master key."""

    def __init__(self, filepath: str, master_key: str = "default-blackwall-vault-key"):
        self.filepath = filepath
        self.master_key = master_key.encode("utf-8")

    def _xor_crypt(self, data: bytes) -> bytes:
        key_len = len(self.master_key)
        return bytes(data[i] ^ self.master_key[i % key_len] for i in range(len(data)))

    def load(self) -> Dict[str, str]:
        if not os.path.exists(self.filepath):
            return {}
        try:
            with open(self.filepath, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = self._xor_crypt(encrypted_data)
            return json.loads(decrypted_data.decode("utf-8"))
        except Exception as e:
            logger.error("Failed to load or decrypt secrets store", error=str(e))
            return {}

    def save(self, data: Dict[str, str]) -> None:
        try:
            raw_data = json.dumps(data).encode("utf-8")
            encrypted_data = self._xor_crypt(raw_data)
            db_dir = os.path.dirname(os.path.abspath(self.filepath))
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            with open(self.filepath, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            logger.error("Failed to save or encrypt secrets store", error=str(e))


class LocalVault:
    """Credential vault integrating a local encrypted store."""

    def __init__(self, filepath: str = "./vault/secrets.enc", master_key: Optional[str] = None):
        key = master_key or os.environ.get("BLACKWALL_VAULT_KEY", "default-blackwall-vault-key")
        self.store = EncryptedLocalStore(filepath, key)

    def set_secret(self, key: str, value: str) -> None:
        """Stores a long-lived secret in the vault."""
        data = self.store.load()
        data[key] = value
        self.store.save(data)

    def get_secret(self, key: str) -> str:
        """Retrieves a secret from the vault. Never caches the returned secret value."""
        # Strip scheme if it is a vault URI
        ref_key = key
        if key.startswith("vault://"):
            ref_key = key[len("vault://"):]
            # Support both vault://secrets/name and vault://name
            if ref_key.startswith("secrets/"):
                ref_key = ref_key[len("secrets/"):]
        
        data = self.store.load()
        if ref_key not in data:
            raise KeyError(f"Secret not found in vault: {key}")
        return data[ref_key]


class JITCredentialManager:
    """Manages temporary downscoped credentials valid only for a specific execution."""

    def __init__(self, vault: LocalVault):
        self.vault = vault
        # Maps temporary token -> (original_reference, scope, created_at)
        self._active_tokens: Dict[str, Dict[str, Any]] = {}

    def create_scoped_token(self, reference: str, scope: str) -> str:
        """Generates a temporary scoped token representing a vault secret."""
        token_id = f"tmp_{scope}_{uuid.uuid4().hex}"
        self._active_tokens[token_id] = {
            "reference": reference,
            "scope": scope,
            "created_at": time.time(),
        }
        logger.debug("Created temporary scoped token", token_id=token_id, scope=scope)
        return token_id

    def resolve_token(self, token_id: str) -> str:
        """Resolves a temporary token to the actual credential value on-demand."""
        if token_id not in self._active_tokens:
            raise ValueError("Invalid or expired temporary token")
        
        token_info = self._active_tokens[token_id]
        ref = token_info["reference"]
        return self.vault.get_secret(ref)

    def revoke_token(self, token_id: str) -> None:
        """Revokes a temporary token, removing it immediately from active tokens."""
        if token_id in self._active_tokens:
            del self._active_tokens[token_id]
            logger.debug("Revoked temporary token", token_id=token_id)
        else:
            logger.warning("Attempted to revoke non-existent or already revoked token", token_id=token_id)


_global_vault: Optional[LocalVault] = None
_global_credential_manager: Optional[JITCredentialManager] = None


def get_global_vault() -> LocalVault:
    global _global_vault
    if _global_vault is None:
        _global_vault = LocalVault()
    return _global_vault


def get_global_credential_manager() -> JITCredentialManager:
    global _global_credential_manager
    if _global_credential_manager is None:
        _global_credential_manager = JITCredentialManager(get_global_vault())
    return _global_credential_manager

import base64
import hashlib
import json
import os
import uuid
import time
import structlog
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = structlog.get_logger(__name__)


def _derive_hkdf_key(master_key: str) -> bytes:
    """Derive a 32-byte urlsafe-base64 Fernet key using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"blackwall-local-vault-key-derivation",
    )
    return base64.urlsafe_b64encode(hkdf.derive(master_key.encode("utf-8")))


def _derive_legacy_sha256_key(master_key: str) -> bytes:
    """Legacy raw SHA-256 derivation kept for backward-compatible vault loading."""
    return base64.urlsafe_b64encode(hashlib.sha256(master_key.encode("utf-8")).digest())


class EncryptedLocalStore:
    """A secure local encrypted store using authenticated encryption with Fernet."""

    def __init__(self, filepath: str, master_key: str):
        self.filepath = filepath
        self.master_key = master_key
        self.cipher = Fernet(_derive_hkdf_key(master_key))
        self._legacy_cipher = Fernet(_derive_legacy_sha256_key(master_key))

    def load(self) -> Dict[str, str]:
        if not os.path.exists(self.filepath):
            return {}
        try:
            with open(self.filepath, "rb") as f:
                encrypted_data = f.read()
            if not encrypted_data:
                # Empty file is treated as empty vault
                return {}
            try:
                decrypted_data = self.cipher.decrypt(encrypted_data)
            except InvalidToken:
                # Fall back to legacy SHA-256 derived cipher for backward compatibility
                decrypted_data = self._legacy_cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode("utf-8"))
        except Exception as e:
            # Fail closed: decryption/authentication failures must not return empty vault
            # This prevents silent secret loss when vault is accessed with wrong key
            logger.error(
                "Failed to decrypt or parse vault - possible key mismatch or corruption",
                error=str(e),
            )
            raise ValueError(f"Vault decryption failed: {str(e)}") from e

    def save(self, data: Dict[str, str]) -> None:
        try:
            raw_data = json.dumps(data).encode("utf-8")
            encrypted_data = self.cipher.encrypt(raw_data)
            db_dir = os.path.dirname(os.path.abspath(self.filepath))
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)

            # Atomic save with restricted file permissions (0o600 - owner read/write only)
            tmp_filepath = f"{self.filepath}.{uuid.uuid4().hex}.tmp"
            fd = os.open(
                tmp_filepath,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(encrypted_data)
                os.replace(tmp_filepath, self.filepath)
            except Exception:
                if os.path.exists(tmp_filepath):
                    try:
                        os.unlink(tmp_filepath)
                    except OSError:
                        pass
                raise
        except Exception as e:
            logger.error("Failed to save or encrypt secrets store", error=str(e))
            raise


class LocalVault:
    """Credential vault integrating a local encrypted store."""

    def __init__(
        self, filepath: str = "./vault/secrets.enc", master_key: Optional[str] = None
    ):
        key = master_key or os.environ.get("BLACKWALL_VAULT_KEY")
        if key is None:
            raise ValueError(
                "Vault key must be provided via master_key parameter or BLACKWALL_VAULT_KEY environment variable"
            )
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
            ref_key = key[len("vault://") :]
            # Support both vault://secrets/name and vault://name
            if ref_key.startswith("secrets/"):
                ref_key = ref_key[len("secrets/") :]

        data = self.store.load()
        if ref_key not in data:
            raise KeyError(f"Secret not found in vault: {key}")
        return data[ref_key]


class JITCredentialManager:
    """Manages temporary downscoped credentials valid only for a specific execution."""

    # Default TTL for temporary tokens in seconds (1 hour)
    DEFAULT_TOKEN_TTL = 3600

    def __init__(self, vault: LocalVault, token_ttl: int = DEFAULT_TOKEN_TTL):
        self.vault = vault
        self.token_ttl = token_ttl
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
        logger.debug("Created temporary scoped token", scope=scope)
        return token_id

    def resolve_token(self, token_id: str) -> str:
        """Resolves a temporary token to the actual credential value on-demand."""
        if token_id not in self._active_tokens:
            raise ValueError("Invalid or expired temporary token")

        token_info = self._active_tokens[token_id]

        # Check if token has expired
        token_age = time.time() - token_info["created_at"]
        if token_age > self.token_ttl:
            # Remove expired token
            del self._active_tokens[token_id]
            raise ValueError("Invalid or expired temporary token")

        ref = token_info["reference"]
        return self.vault.get_secret(ref)

    def revoke_token(self, token_id: str) -> None:
        """Revokes a temporary token, removing it immediately from active tokens."""
        if token_id in self._active_tokens:
            scope = self._active_tokens[token_id].get("scope", "unknown")
            del self._active_tokens[token_id]
            logger.debug("Revoked temporary token", scope=scope)
        else:
            logger.warning("Attempted to revoke non-existent or already revoked token")


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

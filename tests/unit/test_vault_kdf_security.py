"""Unit tests for modernized cryptography vault with HKDF and atomic permissions."""

import base64
import hashlib
import json
import os
import stat
from cryptography.fernet import Fernet
import pytest
from blackwall.security.vault import EncryptedLocalStore


def test_vault_atomic_file_permissions(tmp_path):
    """Verify saved vault file has restricted permissions (0o600)."""
    vault_file = str(tmp_path / "secrets.enc")
    store = EncryptedLocalStore(vault_file, master_key="my-secure-master-key")
    store.save({"secret_token": "super-secret-123"})

    assert os.path.exists(vault_file)
    mode = stat.S_IMODE(os.stat(vault_file).st_mode)
    assert mode == 0o600


def test_vault_legacy_sha256_backward_compatibility(tmp_path):
    """Verify vault encrypted with legacy raw SHA-256 derivation can be decrypted and loaded."""
    vault_file = str(tmp_path / "legacy_secrets.enc")
    master_key = "test-legacy-master-key"

    # Create ciphertext using legacy derivation
    key_bytes = master_key.encode("utf-8")
    legacy_derived_key = base64.urlsafe_b64encode(hashlib.sha256(key_bytes).digest())
    cipher = Fernet(legacy_derived_key)
    raw_payload = json.dumps({"legacy_api_key": "legacy-value-999"}).encode("utf-8")
    encrypted_data = cipher.encrypt(raw_payload)

    with open(vault_file, "wb") as f:
        f.write(encrypted_data)

    # Modern store must be able to load it via backward-compatible decryption fallback
    store = EncryptedLocalStore(vault_file, master_key=master_key)
    data = store.load()
    assert data == {"legacy_api_key": "legacy-value-999"}


def test_vault_invalid_master_key_fails_closed(tmp_path):
    """Verify wrong master key raises ValueError (fails closed)."""
    vault_file = str(tmp_path / "secrets.enc")
    store = EncryptedLocalStore(vault_file, master_key="correct-key")
    store.save({"token": "val"})

    wrong_store = EncryptedLocalStore(vault_file, master_key="wrong-key")
    with pytest.raises(ValueError, match="Vault decryption failed"):
        wrong_store.load()

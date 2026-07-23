"""
Unit tests for SecretVaultSidecar (TASK-I01).
Tests environment variable sterilization, synthetic honey-tokens (BW_SYNTHETIC_*),
exfiltration detection (CRITICAL verdict), and JIT token integration.
"""

import os
import pytest
from blackwall.enterprise.identity import SecretVaultSidecar


@pytest.fixture
def sidecar():
    return SecretVaultSidecar()


def test_sterilize_environment(sidecar):
    mock_env = {
        "PATH": "/usr/bin:/bin",
        "USER": "developer",
        "MOCK_API_KEY_VAL": "BW_SYNTHETIC_MOCK_SECRET_0192",
        "KUBECONFIG_VAR": "/home/user/.kube/config",
        "DATABASE_URL_VAR": "postgres://user:BW_SYNTHETIC_MOCK_SECRET_0192@localhost:5432/db",
    }
    sterilized = sidecar.sterilize_environment(mock_env)

    # Benign variables must remain intact
    assert sterilized["PATH"] == "/usr/bin:/bin"
    assert sterilized["USER"] == "developer"

    # Sensitive variables must be replaced with BW_SYNTHETIC_* honey-tokens
    assert sterilized["MOCK_API_KEY_VAL"].startswith("BW_SYNTHETIC_")
    assert sterilized["KUBECONFIG_VAR"].startswith("BW_SYNTHETIC_")
    assert sterilized["DATABASE_URL_VAR"].startswith("BW_SYNTHETIC_")


def test_evaluate_access_honeytoken_critical(sidecar):
    mock_env = {
        "BW_SYNTHETIC_TEST_SECRET": "BW_SYNTHETIC_MOCK_SECRET_0192",
    }
    sidecar.sterilize_environment(mock_env)

    # Reading synthetic honey-token variable name or value triggers CRITICAL verdict
    res1 = sidecar.evaluate_access("BW_SYNTHETIC_TEST_SECRET")
    assert res1["verdict"] == "CRITICAL"
    assert res1["is_honeytoken"] is True

    res2 = sidecar.evaluate_access("SOME_VAR", "BW_SYNTHETIC_MOCK_SECRET_0192")
    assert res2["verdict"] == "CRITICAL"
    assert res2["is_honeytoken"] is True


def test_evaluate_access_benign_allowed(sidecar):
    mock_env = {
        "PATH": "/usr/bin",
    }
    sidecar.sterilize_environment(mock_env)

    res = sidecar.evaluate_access("PATH", "/usr/bin")
    assert res["verdict"] == "ALLOWED"
    assert res["is_honeytoken"] is False


@pytest.mark.asyncio
async def test_get_jit_credential_integration(sidecar):
    jit_cred = await sidecar.get_jit_credential(role="read-only-worker", ttl_seconds=900)
    assert "token_id" in jit_cred
    assert jit_cred["ttl_seconds"] == 900
    assert jit_cred["role"] == "read-only-worker"

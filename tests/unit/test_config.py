"""
Unit tests for Blackwall Config & GCP Vertex AI Mode Provider Settings.
"""

import os
import pytest
from blackwall.config import configure_provider_env


def test_config_success(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "test-gcp-project")
    monkeypatch.setenv("GCP_LOCATION", "us-central1")
    monkeypatch.setenv("GEMINI_API_KEY", "stale-key-12345")

    settings = configure_provider_env(force=True)

    assert settings.effective_gcp_project == "test-gcp-project"
    assert settings.gcp_location == "us-central1"
    assert settings.gemini_tier == "paid"
    assert os.getenv("GOOGLE_GENAI_USE_VERTEXAI") == "true"
    assert os.getenv("GEMINI_TIER") == "paid"
    assert "GEMINI_API_KEY" not in os.environ


def test_config_google_cloud_project_fallback(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "fallback-gcp-project")

    settings = configure_provider_env(force=True)
    assert settings.effective_gcp_project == "fallback-gcp-project"


def test_config_missing_gcp_project_raises_value_error(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)

    with pytest.raises(
        ValueError, match="GCP_PROJECT or GOOGLE_CLOUD_PROJECT is not configured"
    ):
        configure_provider_env(force=True)


def test_agent_import_without_gcp_project_raises_error(monkeypatch):
    import importlib
    import agent
    import blackwall.config

    # Reset configuration flag
    blackwall.config._env_configured = False
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("BLACKWALL_TEST_MODE", raising=False)

    with pytest.raises(
        ValueError, match="GCP_PROJECT or GOOGLE_CLOUD_PROJECT is not configured"
    ):
        importlib.reload(agent)


def test_repeated_configure_provider_env_purges_newly_injected_keys(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "test-gcp-project")
    configure_provider_env()

    # Simulate subsequent injection of legacy key
    monkeypatch.setenv("GEMINI_API_KEY", "injected-key-6789")
    assert "GEMINI_API_KEY" in os.environ

    # Subsequent call without force must still purge the newly injected key and re-assert env
    configure_provider_env()
    assert "GEMINI_API_KEY" not in os.environ
    assert os.getenv("GOOGLE_GENAI_USE_VERTEXAI") == "true"


def test_get_genai_client_instantiates_vertexai(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "vertex-test-project")
    monkeypatch.setenv("GCP_LOCATION", "us-central1")

    from blackwall.config import get_genai_client
    client = get_genai_client()
    assert client.vertexai is True



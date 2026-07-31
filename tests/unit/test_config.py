"""
Unit tests for Blackwall Config & GCP Vertex AI Mode Provider Settings.
"""

import os
import pytest
from blackwall.config import Settings, configure_provider_env


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

    with pytest.raises(ValueError, match="GCP_PROJECT or GOOGLE_CLOUD_PROJECT is not configured"):
        configure_provider_env(force=True)

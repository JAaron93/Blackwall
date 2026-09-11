import os
from unittest.mock import MagicMock, patch
import pytest

from blackwall.config import Settings, configure_provider_env, get_genai_client
from blackwall.exceptions import APIRateLimitException


# =========================================================================
# Task 7.2: Configuration, Environment & Custom Exceptions Coverage Tests
# =========================================================================

def test_settings_with_gcp_project_env(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "my-custom-gcp-project")
    monkeypatch.setenv("GCP_LOCATION", "us-central1")

    settings = Settings()
    assert settings.gcp_project == "my-custom-gcp-project"
    assert settings.gcp_location == "us-central1"
    assert settings.gemini_tier == "paid"
    assert settings.effective_gcp_project == "my-custom-gcp-project"


def test_settings_with_google_cloud_project_fallback(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "fallback-cloud-project")
    monkeypatch.delenv("GCP_LOCATION", raising=False)

    settings = Settings()
    assert settings.gcp_project == "fallback-cloud-project"
    assert settings.gcp_location == "global"
    assert settings.effective_gcp_project == "fallback-cloud-project"


def test_settings_missing_project_raises_value_error(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)

    settings = Settings()
    assert settings.gcp_project == ""
    with pytest.raises(ValueError, match="GCP_PROJECT or GOOGLE_CLOUD_PROJECT is not configured"):
        _ = settings.effective_gcp_project


def test_configure_provider_env_purges_keys_and_sets_env(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "stale_key_123")
    monkeypatch.setenv("LLM_API_KEY", "stale_key_456")
    monkeypatch.setenv("BACKUP_LLM_API_KEY", "stale_key_789")
    monkeypatch.setenv("GCP_PROJECT", "test-project-123")

    settings = configure_provider_env()

    # Legacy keys purged
    assert "GEMINI_API_KEY" not in os.environ
    assert "LLM_API_KEY" not in os.environ
    assert "BACKUP_LLM_API_KEY" not in os.environ

    # Vertex AI environment variables enforced
    assert os.environ.get("GOOGLE_GENAI_USE_VERTEXAI") == "true"
    assert os.environ.get("GEMINI_TIER") == "paid"
    assert os.environ.get("BLACKWALL_TIER") == "paid"
    assert settings.effective_gcp_project == "test-project-123"


def test_configure_provider_env_missing_project_raises(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)

    with pytest.raises(ValueError, match="GCP_PROJECT or GOOGLE_CLOUD_PROJECT is not configured"):
        configure_provider_env()


@patch("blackwall.config.genai.Client")
def test_get_genai_client_defaults(mock_genai_client, monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "default-proj-999")
    monkeypatch.setenv("GCP_LOCATION", "us-east4")

    client = get_genai_client()
    mock_genai_client.assert_called_once_with(
        vertexai=True,
        project="default-proj-999",
        location="us-east4",
    )
    assert client == mock_genai_client.return_value


@patch("blackwall.config.genai.Client")
def test_get_genai_client_with_explicit_overrides(mock_genai_client, monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "env-project")
    monkeypatch.setenv("GCP_LOCATION", "global")

    client = get_genai_client(project="explicit-override-project", location="europe-west1")
    mock_genai_client.assert_called_once_with(
        vertexai=True,
        project="explicit-override-project",
        location="europe-west1",
    )
    assert client == mock_genai_client.return_value


def test_api_rate_limit_exception():
    exc_default = APIRateLimitException()
    assert str(exc_default) == "Gemini API rate limit exceeded"
    assert isinstance(exc_default, Exception)

    exc_custom = APIRateLimitException("Custom 429 quota exhausted")
    assert str(exc_custom) == "Custom 429 quota exhausted"

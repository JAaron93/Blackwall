"""
Blackwall Configuration & Provider Management
================================================
Central configuration and GCP Vertex AI Mode provider environment manager.

Transitioned exclusively to 100% GCP Vertex AI Mode (Paid Tier via Gemini Enterprise
Agent Platform). Google AI Studio API Key Mode (GEMINI_API_KEY / LLM_API_KEY) and
free/standard tier rate-limits are permanently disabled.
"""

import os
from typing import Optional
from google import genai


class Settings:
    """Blackwall Provider Settings enforcing 100% GCP Vertex AI Mode."""

    def __init__(self, _env_file: Optional[str] = None):
        self.gcp_project: str = (os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT") or "").strip()
        self.gcp_location: str = (os.getenv("GCP_LOCATION") or "global").strip() or "global"
        self.gemini_tier: str = "paid"  # Locked to paid high-throughput tier

    @property
    def effective_gcp_project(self) -> str:
        if not self.gcp_project:
            raise ValueError(
                "GCP_PROJECT or GOOGLE_CLOUD_PROJECT is not configured. "
                "Google AI Studio Key Mode has been permanently removed; this project exclusively uses GCP Vertex AI Mode (Paid Tier). "
                "Please set GCP_PROJECT in your environment or .env file."
            )
        return self.gcp_project


def configure_provider_env() -> Settings:
    """
    Synchronize provider environment variables for GCP Vertex AI Mode.

    - Strictly requires GCP_PROJECT / GOOGLE_CLOUD_PROJECT.
    - Sets GOOGLE_GENAI_USE_VERTEXAI="true".
    - Locks GEMINI_TIER="paid".
    - Purges any stale GEMINI_API_KEY, LLM_API_KEY, or BACKUP_LLM_API_KEY.
    """
    # Purge legacy AI Studio API key environment variables to prevent accidental fallback
    for key in ("GEMINI_API_KEY", "LLM_API_KEY", "BACKUP_LLM_API_KEY"):
        if key in os.environ:
            os.environ.pop(key, None)

    settings = Settings()
    # Force settings evaluation to raise ValueError immediately if GCP_PROJECT is missing
    _ = settings.effective_gcp_project

    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
    os.environ["GEMINI_TIER"] = "paid"
    return settings


def get_genai_client(
    vertexai: bool = True,
    project: Optional[str] = None,
    location: Optional[str] = None,
) -> genai.Client:
    """
    Instantiate a google.genai.Client strictly in Vertex AI Mode.
    """
    settings = configure_provider_env()
    proj = (project or settings.effective_gcp_project).strip()
    loc = (location or settings.gcp_location).strip()
    return genai.Client(vertexai=True, project=proj, location=loc)

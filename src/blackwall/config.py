"""
Blackwall Configuration & Provider Management
================================================
Central configuration and GCP Vertex AI Mode provider environment manager.

Transitioned exclusively to 100% GCP Vertex AI Mode (Paid Tier via Gemini Enterprise
Agent Platform). Google AI Studio API Key Mode (GEMINI_API_KEY / LLM_API_KEY) and
free/standard tier rate-limits are permanently disabled.
"""

import math
import os
from typing import Any, Optional
from google import genai

# --- Single Source of Truth Runtime Constants (Gemini 3.8 Flash) ---
DEFAULT_GEMINI_MODEL: str = "gemini-3.8-flash"
DEFAULT_RAPID_TRIAGE_MODEL: str = "gemini-3.5-flash-lite"
DEFAULT_THINKING_LEVEL: str = "high"
DEFAULT_MAX_OUTPUT_TOKENS: int = 65536
DEFAULT_HTTP_TIMEOUT: float = 120.0

# Task categorization sets for dynamic thinking_level routing
ANALYTICAL_TASK_TYPES: frozenset[str] = frozenset({
    "extractor",
    "analysis",
    "alethiology",
    "evaluator",
    "judge",
    "attribution",
    "forensics",
})

ROUTER_TASK_TYPES: frozenset[str] = frozenset({
    "micro_task",
    "router",
    "classifier",
    "rapid_triage",
})

# Telemetry keys that must be preserved across sanitizers and agent memory
EXCLUDED_TELEMETRY_KEYS: frozenset[str] = frozenset({
    "tokens_used",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "thought",
    "thoughts",
    "thought_tokens",
    "thought_signature",
    "think",
    "reasoning",
})


def get_gemini_thinking_level(
    model: str | None = None,
    default: str | None = None,
    *,
    task_type: str | None = None,
    settings: Any | None = None,
) -> str | None:
    """
    Resolve thinking level enforcing an immutable HIGH floor for analytical tasks.
    """
    allow_downgrade = (
        os.getenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", "").strip().lower() == "true"
        or getattr(settings, "GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", False)
    )

    # 1. Enforce strict analytical floor: analytical agents must never be throttled below HIGH
    # unless an explicit downgrade flag is set (e.g. for specialized test fixtures)
    if task_type in ANALYTICAL_TASK_TYPES and not allow_downgrade:
        return "high"

    # 2. Explicit environment variable override for non-analytical tasks (or when downgrade allowed)
    env_level = os.getenv("GEMINI_THINKING_LEVEL")
    if env_level and env_level.strip():
        return env_level.strip().lower()

    if default is not None:
        return default

    # 3. Bypass deep thinking for micro-tasks and routers
    if task_type in ROUTER_TASK_TYPES:
        return "low"

    # 4. Settings configuration override if explicitly configured
    settings_level = getattr(settings, "GEMINI_THINKING_LEVEL", None)
    if settings_level and str(settings_level).strip():
        return str(settings_level).strip().lower()

    # 5. Default to HIGH for Gemini 3.8 models
    if model and "3.8" in model:
        return "high"
    return None


def get_gemini_max_output_tokens(
    configured: int | None = None,
    *,
    task_type: str | None = None,
    settings: Any | None = None,
) -> int:
    """
    Resolve maximum output token ceiling, enforcing 64K floor for analytical tasks.
    Guarantees finite, strictly positive (>0) token limits across all environments.
    """
    allow_downgrade = (
        os.getenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", "").strip().lower() == "true"
        or getattr(settings, "GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", False)
    )

    def _is_valid_tokens(t: Any) -> bool:
        return isinstance(t, int) and t > 0

    valid_configured = configured if _is_valid_tokens(configured) else DEFAULT_MAX_OUTPUT_TOKENS

    env_tokens = os.getenv("GEMINI_MAX_OUTPUT_TOKENS")
    if env_tokens and env_tokens.strip().isdigit():
        try:
            parsed = int(env_tokens)
            val = parsed if _is_valid_tokens(parsed) else valid_configured
        except (ValueError, TypeError):
            val = valid_configured
    else:
        val = valid_configured

    if task_type in ANALYTICAL_TASK_TYPES and not allow_downgrade:
        return max(val, DEFAULT_MAX_OUTPUT_TOKENS)
    return val


def get_gemini_http_timeout(
    configured: float | None = None,
    *,
    task_type: str | None = None,
    settings: Any | None = None,
) -> float:
    """
    Resolve request-level HTTP timeout, enforcing 120s floor for analytical tasks.
    Guarantees finite, strictly positive (>0) timeouts across all environments.
    """
    allow_downgrade = (
        os.getenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", "").strip().lower() == "true"
        or getattr(settings, "GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", False)
    )

    def _is_valid(t: Any) -> bool:
        return isinstance(t, (int, float)) and math.isfinite(t) and t > 0.0

    valid_configured = configured if _is_valid(configured) else DEFAULT_HTTP_TIMEOUT

    env_timeout = os.getenv("GEMINI_HTTP_TIMEOUT")
    if env_timeout and env_timeout.strip():
        try:
            parsed = float(env_timeout)
            val = parsed if _is_valid(parsed) else valid_configured
        except (ValueError, TypeError):
            val = valid_configured
    else:
        val = valid_configured

    if task_type in ANALYTICAL_TASK_TYPES and not allow_downgrade:
        return max(val, DEFAULT_HTTP_TIMEOUT)
    return val


class Settings:
    """Blackwall Provider Settings enforcing 100% GCP Vertex AI Mode."""

    def __init__(self, _env_file: Optional[str] = None):
        self.gcp_project: str = (
            os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT") or ""
        ).strip()
        self.gcp_location: str = (
            os.getenv("GCP_LOCATION") or "global"
        ).strip() or "global"
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


_env_configured: bool = True


def configure_provider_env(force: bool = False) -> Settings:
    """
    Synchronize provider environment variables for GCP Vertex AI Mode.

    - Strictly requires GCP_PROJECT / GOOGLE_CLOUD_PROJECT.
    - Sets GOOGLE_GENAI_USE_VERTEXAI="true".
    - Locks GEMINI_TIER="paid" and BLACKWALL_TIER="paid".
    - Purges any stale GEMINI_API_KEY, LLM_API_KEY, or BACKUP_LLM_API_KEY.
    """
    global _env_configured

    # Always purge legacy AI Studio API key environment variables to prevent accidental fallback
    for key in ("GEMINI_API_KEY", "LLM_API_KEY", "BACKUP_LLM_API_KEY"):
        os.environ.pop(key, None)

    # Always enforce Vertex AI mode and paid tier environment variables
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
    os.environ["GEMINI_TIER"] = "paid"
    os.environ["BLACKWALL_TIER"] = "paid"

    settings = Settings()
    # Force settings evaluation to raise ValueError immediately if GCP_PROJECT is missing
    _ = settings.effective_gcp_project
    _env_configured = True
    return settings


def get_genai_client(
    vertexai: bool = True,
    project: Optional[str] = None,
    location: Optional[str] = None,
    timeout: Optional[float] = None,
    **kwargs: Any,
) -> genai.Client:
    """
    Instantiate a google.genai.Client strictly in Vertex AI Mode with request-level HTTP timeout.
    """
    settings = configure_provider_env()
    proj = (project or settings.effective_gcp_project).strip()
    loc = (location or settings.gcp_location).strip()

    client_kwargs: dict[str, Any] = {
        "vertexai": True,
        "project": proj,
        "location": loc,
    }
    if timeout is not None:
        from google.genai import types

        client_kwargs["http_options"] = types.HttpOptions(
            timeout=get_gemini_http_timeout(configured=timeout)
        )
    client_kwargs.update(kwargs)
    return genai.Client(**client_kwargs)

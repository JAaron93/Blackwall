"""
Judge Agent Factory for Google Antigravity SDK (`blackwall.eval.judge_factory`).

Instantiates autonomous Agent-as-a-Judge agents running in Vertex AI Standard Mode
with strict response schemas (Pydantic rubrics) and paid-tier quota verification.
"""

from __future__ import annotations

import logging
import os
from types import TracebackType
from typing import Any, Self

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Attempt to import real Google Antigravity SDK, or provide robust stubs if unavailable
try:
    from google.antigravity import Agent, LocalAgentConfig, types
    from google.antigravity.types import AgentBehavior, CapabilitiesConfig
    _ANTIGRAVITY_AVAILABLE = True
except ImportError:
    _ANTIGRAVITY_AVAILABLE = False

    # Define compatibility classes for environments where google-antigravity is not pre-installed
    class AgentBehavior:
        AUTONOMOUS = "AUTONOMOUS"
        INTERACTIVE = "INTERACTIVE"

    class CapabilitiesConfig:
        def __init__(self, agent_behavior: str = AgentBehavior.AUTONOMOUS, **kwargs: Any) -> None:
            self.agent_behavior = agent_behavior
            self.extra = kwargs

    class types:  # type: ignore[no-redef]
        AgentBehavior = AgentBehavior
        CapabilitiesConfig = CapabilitiesConfig

    class LocalAgentConfig:
        def __init__(
            self,
            vertex: bool = True,
            project: str | None = None,
            location: str = "us-central1",
            model: str = "gemini-3.8-flash",
            response_schema: type[BaseModel] | None = None,
            capabilities: CapabilitiesConfig | None = None,
            thinking_level: str | None = None,
            max_output_tokens: int | None = None,
            timeout: float | None = None,
            **kwargs: Any,
        ) -> None:
            self.vertex = vertex
            self.project = project
            self.location = location
            self.model = model
            self.response_schema = response_schema
            self.capabilities = capabilities or CapabilitiesConfig()
            self.thinking_level = thinking_level
            self.max_output_tokens = max_output_tokens
            self.timeout = timeout
            self.extra = kwargs

    class Agent:  # type: ignore[no-redef]
        def __init__(self, config: LocalAgentConfig) -> None:
            self.config = config

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: TracebackType | None,
        ) -> None:
            pass

        async def chat(self, prompt: str) -> str:
            raise RuntimeError(
                "google-antigravity SDK is not installed in the local environment. "
                "Agent chat must be mocked in tests or executed in a supported GCP environment."
            )


def validate_evaluation_tier_contract() -> None:
    """
    Validate the 300+ RPM paid-tier quota contract for Agent-as-a-Judge evaluation workloads.

    Enforces GEMINI_TIER=paid and BLACKWALL_TIER=paid, and ensures GCP_PROJECT is configured.
    """
    gemini_tier = os.getenv("GEMINI_TIER", "").strip().lower()
    blackwall_tier = os.getenv("BLACKWALL_TIER", "").strip().lower()
    gcp_project = os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT")

    errors = []
    if gemini_tier != "paid":
        errors.append(
            f"GEMINI_TIER must be set to 'paid' (found '{os.getenv('GEMINI_TIER', '')}'). "
            "Evaluation judges require the 300+ RPM quota contract."
        )
    if blackwall_tier != "paid":
        errors.append(
            f"BLACKWALL_TIER must be set to 'paid' (found '{os.getenv('BLACKWALL_TIER', '')}'). "
            "Blackwall evaluation pipeline requires the paid-tier feature contract."
        )
    if not gcp_project or not gcp_project.strip():
        errors.append(
            "GCP_PROJECT (or GOOGLE_CLOUD_PROJECT) must be set for Vertex AI evaluation."
        )

    if errors:
        error_msg = " [QUOTA CONTRACT ERROR] " + " | ".join(errors)
        logger.error(error_msg)
        raise ValueError(error_msg)


def create_judge_agent(
    domain: str,
    rubric_schema: type[BaseModel],
    model: str | None = None,
    enforce_tier: bool = True,
    thinking_level: str | None = None,
    max_output_tokens: int | None = None,
    timeout: float | None = None,
) -> Agent:
    """
    Create an autonomous Antigravity SDK Agent configured for evaluation scoring.

    Args:
        domain: Target evaluation domain identifier.
        rubric_schema: Pydantic rubric model class for structured response output.
        model: Model name override (defaults to BLACKWALL_JUDGE_MODEL or 'gemini-3.8-flash').
        enforce_tier: If True, asserts GEMINI_TIER=paid, BLACKWALL_TIER=paid, and GCP_PROJECT.
        thinking_level: Optional thinking level override (defaults to get_gemini_thinking_level, enforcing HIGH floor).
        max_output_tokens: Optional token ceiling override (defaults to get_gemini_max_output_tokens, 64K floor).
        timeout: Optional request timeout override (defaults to get_gemini_http_timeout, 120s floor).

    Returns:
        Configured Agent instance.
    """
    from blackwall.config import (
        get_gemini_http_timeout,
        get_gemini_max_output_tokens,
        get_gemini_thinking_level,
    )

    if enforce_tier:
        validate_evaluation_tier_contract()

    project = os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project or not project.strip():
        if enforce_tier:
            raise ValueError("GCP_PROJECT (or GOOGLE_CLOUD_PROJECT) must be set.")
        project = "blackwall-eval-project"
    else:
        project = project.strip()

    location = os.getenv("GCP_LOCATION") or os.getenv("GOOGLE_CLOUD_LOCATION") or "us-central1"
    effective_model = model or os.getenv("BLACKWALL_JUDGE_MODEL") or "gemini-3.8-flash"
    effective_thinking_level = thinking_level or get_gemini_thinking_level(
        model=effective_model, task_type="judge"
    )
    effective_max_output_tokens = max_output_tokens or get_gemini_max_output_tokens(
        task_type="judge"
    )
    effective_timeout = timeout or get_gemini_http_timeout(task_type="judge")

    capabilities = types.CapabilitiesConfig(
        agent_behavior=types.AgentBehavior.AUTONOMOUS,
    )

    config = LocalAgentConfig(
        vertex=True,
        project=project,
        location=location,
        model=effective_model,
        response_schema=rubric_schema,
        capabilities=capabilities,
        thinking_level=effective_thinking_level,
        max_output_tokens=effective_max_output_tokens,
        timeout=effective_timeout,
    )

    logger.info(
        "Created judge agent for domain '%s' using model '%s' in region '%s' (thinking_level=%s, max_output_tokens=%s, timeout=%s)",
        domain,
        effective_model,
        location,
        effective_thinking_level,
        effective_max_output_tokens,
        effective_timeout,
    )
    return Agent(config=config)

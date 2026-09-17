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

from blackwall.validators import normalize_text

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
            project = (
                self.config.project
                or os.getenv("GCP_PROJECT")
                or os.getenv("GOOGLE_CLOUD_PROJECT")
            )
            if not project or not project.strip():
                raise RuntimeError(
                    "google-antigravity SDK is not installed in the local environment. "
                    "Agent chat must be mocked in tests or executed in a supported GCP environment."
                )

            try:
                from google import genai
                from google.genai import types
            except ImportError:
                raise RuntimeError(
                    "google-antigravity SDK is not installed in the local environment. "
                    "Agent chat must be mocked in tests or executed in a supported GCP environment."
                )

            location = self.config.location or "global"
            if location == "us-central1" and os.getenv("GCP_LOCATION", "").lower() == "global":
                location = "global"

            timeout_ms = int((self.config.timeout or 120.0) * 1000.0)
            client = genai.Client(
                vertexai=self.config.vertex,
                project=project.strip(),
                location=location,
                http_options=types.HttpOptions(timeout=timeout_ms),
            )

            gen_config = types.GenerateContentConfig()
            if self.config.response_schema is not None:
                gen_config.response_mime_type = "application/json"
                gen_config.response_schema = self.config.response_schema

            if self.config.thinking_level:
                try:
                    level = self.config.thinking_level.upper()
                    gen_config.thinking_config = types.ThinkingConfig(thinking_level=level)
                except Exception:
                    pass

            if self.config.max_output_tokens:
                gen_config.max_output_tokens = self.config.max_output_tokens

            target_model = self.config.model or "gemini-3.8-flash"
            try:
                response = await client.aio.models.generate_content(
                    model=target_model,
                    contents=prompt,
                    config=gen_config,
                )
            except Exception as model_err:
                err_str = str(model_err)
                is_quota_or_timeout = any(
                    token in err_str
                    for token in ("429", "RESOURCE_EXHAUSTED", "504", "DEADLINE_EXCEEDED", "TimeoutError", "timeout")
                ) or isinstance(model_err, TimeoutError)
                if is_quota_or_timeout and target_model != "gemini-3.5-flash-lite":
                    logger.warning(
                        "Primary judge model '%s' encountered error (%s); attempting fallback to 'gemini-3.5-flash-lite'",
                        target_model,
                        err_str,
                    )
                    response = await client.aio.models.generate_content(
                        model="gemini-3.5-flash-lite",
                        contents=prompt,
                        config=gen_config,
                    )
                else:
                    raise
            return response.text or ""


def validate_evaluation_tier_contract() -> None:
    """
    Validate the 300+ RPM paid-tier quota contract for Agent-as-a-Judge evaluation workloads.

    Enforces GEMINI_TIER=paid and BLACKWALL_TIER=paid, and ensures GCP_PROJECT is configured.
    """
    gemini_tier = normalize_text(os.getenv("GEMINI_TIER", ""))
    blackwall_tier = normalize_text(os.getenv("BLACKWALL_TIER", ""))
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

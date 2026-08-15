"""Weave evaluation tracking configuration and initialization infrastructure.

Subtask 22.1: Weave Configuration and Initialization Infrastructure.
"""

from __future__ import annotations

import logging
import netrc
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

try:
    import weave
except ImportError:  # pragma: no cover
    weave = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@dataclass
class WeaveConfig:
    """Configuration settings for Weave evaluation tracking."""

    project_name: str = "blackwall-advanced-threat-detection"
    entity: str | None = None
    offline_mode: bool = False
    parallelism: int = 1
    tags: list[str] = field(default_factory=list)


def has_wandb_credentials() -> bool:
    """Check whether valid Weights & Biases credentials exist on the host."""
    if os.getenv("WANDB_API_KEY"):
        return True

    # Check ~/.netrc or netrc
    try:
        netrc_auth = netrc.netrc()
        if netrc_auth.authenticators("api.wandb.ai") or netrc_auth.authenticators("wandb.ai"):
            return True
    except Exception:
        pass

    # Check ~/.config/wandb/settings or ~/.wandb/settings
    try:
        home = Path.home()
        candidate_paths = [
            home / ".config" / "wandb" / "settings",
            home / ".wandb" / "settings",
        ]
        for p in candidate_paths:
            if p.exists() and p.is_file():
                content = p.read_text(encoding="utf-8")
                if "api_key" in content or "api.wandb.ai" in content:
                    return True
    except Exception:
        pass

    return False


def should_enable_weave() -> bool:
    """Determine if Weave tracking should be enabled based on priority rules.

    Priority order:
    1. WEAVE_DISABLED=true -> False
    2. WEAVE_OFFLINE=true -> True (local storage, no cloud credentials)
    3. WANDB_API_KEY set -> True
    4. netrc/config file credentials -> True
    5. None of above -> False
    """
    disabled_env = os.getenv("WEAVE_DISABLED", "").strip().lower()
    if disabled_env in ("true", "1", "yes"):
        return False

    offline_env = os.getenv("WEAVE_OFFLINE", "").strip().lower()
    if offline_env in ("true", "1", "yes"):
        return True

    if os.getenv("WANDB_API_KEY"):
        return True

    return has_wandb_credentials()


def load_weave_config(config_path: str | None = None) -> WeaveConfig:
    """Load Weave configuration from a YAML file, falling back to defaults."""
    default_config = WeaveConfig()
    if not config_path:
        return default_config

    path = Path(config_path)
    if not path.exists() or not path.is_file():
        logger.warning(
            "Weave config file '%s' not found. Falling back to default configuration.",
            config_path,
        )
        return default_config

    try:
        with open(path, "r", encoding="utf-8") as f:
            data: Any = yaml.safe_load(f)

        if not isinstance(data, dict):
            logger.warning(
                "Invalid YAML content in '%s'. Falling back to default configuration.",
                config_path,
            )
            return default_config

        weave_data = data.get("weave", data)
        if not isinstance(weave_data, dict):
            return default_config

        return WeaveConfig(
            project_name=weave_data.get("project_name", default_config.project_name),
            entity=weave_data.get("entity", default_config.entity),
            offline_mode=bool(weave_data.get("offline_mode", default_config.offline_mode)),
            parallelism=int(weave_data.get("parallelism", default_config.parallelism)),
            tags=list(weave_data.get("tags", default_config.tags)),
        )
    except Exception as exc:
        logger.warning(
            "Error loading Weave config from '%s': %s. Using default configuration.",
            config_path,
            exc,
        )
        return default_config


def init_weave(config: WeaveConfig | None = None) -> bool:
    """Initialize Weave evaluation tracking.

    Returns True if initialized successfully, False if disabled or failed.
    """
    if not should_enable_weave():
        logger.info("Weave tracking is disabled or no valid credentials found.")
        return False

    if config is None:
        config = load_weave_config()

    try:
        if config.offline_mode or os.getenv("WEAVE_OFFLINE", "").strip().lower() in (
            "true",
            "1",
            "yes",
        ):
            os.environ["WEAVE_OFFLINE"] = "true"

        if weave is None:
            logger.warning("weave package is not installed. Tracking disabled.")
            return False

        init_kwargs: dict[str, Any] = {"project_name": config.project_name}
        if config.entity:
            init_kwargs["entity"] = config.entity

        weave.init(**init_kwargs)
        logger.info("Weave initialized successfully for project '%s'.", config.project_name)
        return True
    except Exception as exc:
        logger.error("Failed to initialize Weave: %s", exc)
        return False

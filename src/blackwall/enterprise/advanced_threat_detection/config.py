"""Configuration schema for Blackwall Advanced Threat Detection (Pillar 6)."""

import os
from typing import Any, Optional
from pydantic import BaseModel, Field, model_validator

from blackwall.enterprise.advanced_threat_detection.enums import AlertSeverity

ENV_PREFIX = "BLACKWALL_ATD_"


class AdvancedThreatDetectionConfig(BaseModel):
    """Configuration settings for Advanced Threat Detection orchestrator and engines."""

    # Storage and Database Persistence
    database_url: Optional[str] = None
    in_memory: bool = True
    min_connections: int = Field(default=1, gt=0)
    max_connections: int = Field(default=10, gt=0)
    retention_period_days: int = Field(default=90, gt=0)

    # Detection Engine Toggles
    enable_path_correlation: bool = True
    enable_swarm_detection: bool = True
    enable_exploit_analysis: bool = True
    enable_ailm_tracking: bool = True
    enable_c2_detection: bool = True
    enable_k8s_defense: bool = True
    enable_registry_monitor: bool = True
    enable_active_reaction: bool = True
    enable_inbound_filter: bool = True
    enable_prompt_injection: bool = True
    enable_quota_enforcer: bool = True

    # Breach Defense Parameters
    inbound_rate_limit: int = Field(default=100, gt=0)
    inbound_sliding_window_sec: int = Field(default=60, gt=0)
    inbound_enforce_loopback: bool = True
    prompt_injection_confidence_threshold: float = Field(default=0.5, gt=0.0, le=1.0)
    prompt_injection_critical_threshold: float = Field(default=0.85, gt=0.0, le=1.0)
    prompt_injection_redaction_placeholder: str = "[REDACTED_PROMPT_INJECTION]"
    quota_token_burn_rate_limit: float = Field(default=500.0, gt=0.0)
    quota_request_velocity_limit: float = Field(default=50.0, gt=0.0)
    quota_sliding_window_sec: float = Field(default=60.0, gt=0.0)
    quota_quarantine_duration_sec: float = Field(default=300.0, gt=0.0)

    # Engine Thresholds and Analysis Parameters
    min_path_length: int = Field(default=2, ge=2)
    temporal_window_seconds: float = Field(default=300.0, gt=0.0)
    swarm_correlation_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    swarm_min_agents: int = Field(default=2, ge=2)
    exploit_novelty_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    c2_beaconing_threshold: float = Field(default=0.25, ge=0.0, le=1.0)
    k8s_min_exfiltration_events: int = Field(default=3, gt=0)
    registry_min_probing_events: int = Field(default=5, gt=0)

    # Alert Bus Settings
    alert_min_severity: AlertSeverity = AlertSeverity.LOW
    alert_batch_size: int = Field(default=100, gt=0)
    alert_flush_interval_seconds: float = Field(default=1.0, gt=0.0)

    # Stream Collection & Buffering
    event_buffer_size: int = Field(default=10000, gt=0)
    reconnect_max_attempts: int = Field(default=5, ge=0)
    reconnect_backoff_base: float = Field(default=0.1, gt=0.0)

    # Throttling & Resilience
    max_events_per_second: int = Field(default=1000, gt=0)
    max_memory_mb: int = Field(default=2048, gt=0)
    safe_execution_timeout: float = Field(default=5.0, gt=0.0)

    @model_validator(mode="after")
    def validate_connection_bounds(self) -> "AdvancedThreatDetectionConfig":
        """Ensure max_connections >= min_connections."""
        if self.max_connections < self.min_connections:
            raise ValueError(
                f"max_connections ({self.max_connections}) must be >= min_connections ({self.min_connections})"
            )
        return self

    @classmethod
    def from_env(
        cls, env: Optional[dict[str, str]] = None
    ) -> "AdvancedThreatDetectionConfig":
        """Construct configuration instance from environment variables with BLACKWALL_ATD_ prefix."""
        source_env = env if env is not None else dict(os.environ)
        kwargs: dict[str, Any] = {}

        field_types = {name: field.annotation for name, field in cls.model_fields.items()}

        for env_key, raw_val in source_env.items():
            if not env_key.startswith(ENV_PREFIX):
                continue

            config_key = env_key[len(ENV_PREFIX) :].lower()
            if config_key not in field_types:
                continue

            target_type = field_types[config_key]

            # Coerce boolean
            if target_type is bool or target_type == bool:
                val_str = raw_val.strip().lower()
                kwargs[config_key] = val_str in ("1", "true", "yes", "on", "enabled")
            # Coerce int
            elif target_type is int or target_type == int:
                try:
                    kwargs[config_key] = int(raw_val)
                except ValueError:
                    kwargs[config_key] = raw_val
            # Coerce float
            elif target_type is float or target_type == float:
                try:
                    kwargs[config_key] = float(raw_val)
                except ValueError:
                    kwargs[config_key] = raw_val
            # Coerce AlertSeverity enum
            elif target_type is AlertSeverity or target_type == AlertSeverity:
                try:
                    kwargs[config_key] = AlertSeverity(raw_val.upper())
                except ValueError:
                    kwargs[config_key] = raw_val
            else:
                kwargs[config_key] = raw_val

        return cls(**kwargs)

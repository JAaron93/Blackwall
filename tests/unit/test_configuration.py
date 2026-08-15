"""Unit tests for AdvancedThreatDetectionConfig (Task 21.3)."""

import os
from unittest.mock import patch
import pytest
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.config import (
    AdvancedThreatDetectionConfig,
)
from blackwall.enterprise.advanced_threat_detection.enums import AlertSeverity


def test_default_configuration():
    """Verify default configuration values."""
    config = AdvancedThreatDetectionConfig()

    assert config.in_memory is True
    assert config.min_connections == 1
    assert config.max_connections == 10
    assert config.retention_period_days == 90

    # Engine toggles
    assert config.enable_path_correlation is True
    assert config.enable_swarm_detection is True
    assert config.enable_exploit_analysis is True
    assert config.enable_ailm_tracking is True
    assert config.enable_c2_detection is True
    assert config.enable_k8s_defense is True
    assert config.enable_registry_monitor is True

    # Engine parameters
    assert config.min_path_length == 2
    assert config.temporal_window_seconds == 300.0
    assert config.swarm_correlation_threshold == 0.75
    assert config.swarm_min_agents == 2

    # Alert bus
    assert config.alert_min_severity == AlertSeverity.LOW
    assert config.alert_batch_size == 100
    assert config.alert_flush_interval_seconds == 1.0

    # Throttling & Resilience
    assert config.event_buffer_size == 10000
    assert config.reconnect_max_attempts == 5
    assert config.max_events_per_second == 1000
    assert config.safe_execution_timeout == 5.0


def test_custom_configuration():
    """Verify custom parameter initialization."""
    config = AdvancedThreatDetectionConfig(
        database_url="postgresql://user:pass@localhost:5432/testdb",
        in_memory=False,
        min_connections=2,
        max_connections=20,
        retention_period_days=30,
        enable_c2_detection=False,
        min_path_length=3,
        temporal_window_seconds=600.0,
        alert_min_severity=AlertSeverity.HIGH,
        max_events_per_second=5000,
    )

    assert config.database_url == "postgresql://user:pass@localhost:5432/testdb"
    assert config.in_memory is False
    assert config.min_connections == 2
    assert config.max_connections == 20
    assert config.retention_period_days == 30
    assert config.enable_c2_detection is False
    assert config.min_path_length == 3
    assert config.temporal_window_seconds == 600.0
    assert config.alert_min_severity == AlertSeverity.HIGH
    assert config.max_events_per_second == 5000


def test_validation_constraints():
    """Verify validation constraints reject invalid parameter values."""
    # min_connections > 0
    with pytest.raises(ValidationError):
        AdvancedThreatDetectionConfig(min_connections=0)

    # max_connections >= min_connections
    with pytest.raises(ValidationError):
        AdvancedThreatDetectionConfig(min_connections=10, max_connections=5)

    # retention_period_days > 0
    with pytest.raises(ValidationError):
        AdvancedThreatDetectionConfig(retention_period_days=0)

    # min_path_length >= 2
    with pytest.raises(ValidationError):
        AdvancedThreatDetectionConfig(min_path_length=1)

    # swarm_correlation_threshold in [0.0, 1.0]
    with pytest.raises(ValidationError):
        AdvancedThreatDetectionConfig(swarm_correlation_threshold=1.5)

    with pytest.raises(ValidationError):
        AdvancedThreatDetectionConfig(swarm_correlation_threshold=-0.1)

    # max_events_per_second > 0
    with pytest.raises(ValidationError):
        AdvancedThreatDetectionConfig(max_events_per_second=0)


def test_environment_variable_overrides():
    """Verify environment variable overrides with BLACKWALL_ATD_ prefix."""
    env_vars = {
        "BLACKWALL_ATD_DATABASE_URL": "postgresql://testuser:testpass@db.local:5432/atd",
        "BLACKWALL_ATD_IN_MEMORY": "false",
        "BLACKWALL_ATD_MIN_CONNECTIONS": "5",
        "BLACKWALL_ATD_MAX_CONNECTIONS": "25",
        "BLACKWALL_ATD_ENABLE_SWARM_DETECTION": "false",
        "BLACKWALL_ATD_MIN_PATH_LENGTH": "4",
        "BLACKWALL_ATD_TEMPORAL_WINDOW_SECONDS": "120.5",
        "BLACKWALL_ATD_ALERT_MIN_SEVERITY": "CRITICAL",
        "BLACKWALL_ATD_MAX_EVENTS_PER_SECOND": "2500",
    }

    with patch.dict(os.environ, env_vars, clear=False):
        config = AdvancedThreatDetectionConfig.from_env()

        assert config.database_url == "postgresql://testuser:testpass@db.local:5432/atd"
        assert config.in_memory is False
        assert config.min_connections == 5
        assert config.max_connections == 25
        assert config.enable_swarm_detection is False
        assert config.min_path_length == 4
        assert config.temporal_window_seconds == 120.5
        assert config.alert_min_severity == AlertSeverity.CRITICAL
        assert config.max_events_per_second == 2500


def test_from_env_with_explicit_dict():
    """Verify from_env method accepts explicit dictionary."""
    custom_env = {
        "BLACKWALL_ATD_RETENTION_PERIOD_DAYS": "45",
        "BLACKWALL_ATD_ENABLE_K8S_DEFENSE": "0",
        "BLACKWALL_ATD_ALERT_MIN_SEVERITY": "MEDIUM",
    }

    config = AdvancedThreatDetectionConfig.from_env(env=custom_env)

    assert config.retention_period_days == 45
    assert config.enable_k8s_defense is False
    assert config.alert_min_severity == AlertSeverity.MEDIUM

"""Enums for Blackwall Advanced Threat Detection."""

from enum import Enum


class EventSource(str, Enum):
    """Source pillar of a normalized threat detection event."""

    KERNEL_SYSCALL = "kernel_syscall"
    TOOL_CALL = "tool_call"
    IDENTITY_ACCESS = "identity_access"
    PIPELINE_EXECUTION = "pipeline_execution"
    FORENSIC_ALERT = "forensic_alert"


class ExploitCategory(str, Enum):
    """Classification categories for zero-day exploit analysis."""

    RCE = "remote_code_execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_THEFT = "credential_theft"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"


class AlertSeverity(str, Enum):
    """Severity levels for threat detection alerts."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


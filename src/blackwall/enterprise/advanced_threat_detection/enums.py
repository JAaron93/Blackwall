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


class ReactionActionType(str, Enum):
    """Action types for automated mitigation by Active Reaction Engine."""

    EBPF_DROP = "EBPF_DROP"
    MESH_SIGNATURE_BROADCAST = "MESH_SIGNATURE_BROADCAST"
    REVOKE_IDENTITY_TOKENS = "REVOKE_IDENTITY_TOKENS"


class InboundProtocolType(str, Enum):
    """Protocol types for incoming agent-to-agent and MCP communication."""

    MCP_SSE = "MCP_SSE"
    MCP_STDIO = "MCP_STDIO"
    A2A_REST = "A2A_REST"


class InboundMethodType(str, Enum):
    """RPC method types for incoming protocol requests."""

    TOOLS_CALL = "tools/call"
    PROMPT_SUBMIT = "prompt/submit"




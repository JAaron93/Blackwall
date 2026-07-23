"""
Blackwall Enterprise Security Mesh Extension
Modularized subpackage for enterprise multi-host security features:
- C/Python eBPF kernel interception
- ZeroMQ pub/sub threat mesh broadcast
- Ephemeral Identity Sidecar & JIT secret vault
- Data Pipeline wrappers & AST micro-sandbox isolation
- Dual-Mode Local Forensic Triage Engine
- Enterprise Open-Source MCP Server Adapters
"""

__version__ = "1.0.0-enterprise"
ENTERPRISE_ENABLED = True

from blackwall.enterprise.identity import SecretVaultSidecar
from blackwall.enterprise.mcp import ContainerSandboxMCPAdapter, VaultMCPAdapter
from blackwall.enterprise.pipeline import (
    ASTPipelineFilter,
    PipelineSandboxManager,
    guard_pipeline,
)

__all__ = [
    "__version__",
    "ENTERPRISE_ENABLED",
    "SecretVaultSidecar",
    "VaultMCPAdapter",
    "ContainerSandboxMCPAdapter",
    "ASTPipelineFilter",
    "PipelineSandboxManager",
    "guard_pipeline",
]



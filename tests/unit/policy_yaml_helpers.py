"""
Shared YAML helpers for Blackwall structural-gating unit tests.

Centralises the policy YAML template and the two utility functions that
tests/unit/test_structural_gating.py previously defined locally.  Import
from here so the template string has a single canonical source of truth.
"""

from __future__ import annotations

import os
import tempfile

# ---------------------------------------------------------------------------
# Canonical policy YAML template
# ---------------------------------------------------------------------------

BASE_YAML_TEMPLATE: str = """
version: "{version}"
global:
  threatThreshold: 0.75
  quarantineThreshold: 0.5
  enableStructuralGating: true
  enableSemanticGating: true
environmentRoles:
  sandbox:
    allowedTools: ["read_file", "write_file"]
    blockedTools: ["execute_bash"]
    requireSemanticReview: false
    maxThreatScore: 0.8
  production:
    allowedTools: ["read_file"]
    blockedTools: ["execute_bash", "write_file"]
    requireSemanticReview: true
    maxThreatScore: 0.5
structuralRules:
{rules}
semanticGuidelines:
  - "Test guideline"
mcpServers:
  gti:
    enabled: true
    apiKey: "vault://gti"
    cacheEnabled: true
    cacheTTL: 3600
    timeout: 5000
  codebaseMemory:
    enabled: true
    apiKey: "vault://cbm"
    cacheEnabled: true
    cacheTTL: 3600
    timeout: 2000
threatSignatureGraph:
  dbPath: "/tmp/test-tsg.db"
  walMode: true
  maxConnections: 10
  similarityThreshold: 0.85
  ttlSeconds: 3600
  maxSignatures: 1000
  embeddingDimension: 384
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_yaml(rules_yaml: str, version: str = "1.0.0") -> str:
    """Render ``BASE_YAML_TEMPLATE`` with the given *rules_yaml* block.

    Args:
        rules_yaml: YAML fragment for the ``structuralRules`` list.  May be
                    empty string to produce an empty rules list.
        version:    SemVer string to embed in the policy header.

    Returns:
        Complete policy YAML string ready for ``StructuralGatingEngine.load_policy``.
    """
    indented_rules = (
        "\n".join("  " + line for line in rules_yaml.strip().split("\n"))
        if rules_yaml.strip()
        else ""
    )
    if not indented_rules:
        indented_rules = "  []"
    return BASE_YAML_TEMPLATE.format(version=version, rules=indented_rules)


def write_temp_yaml(content: str) -> str:
    """Write *content* to a temporary ``.yaml`` file and return its path.

    The caller is responsible for removing the file after use (typically via
    a ``try/finally`` block with ``os.remove``).
    """
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path

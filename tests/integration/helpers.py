"""
Shared helpers for Blackwall integration tests.

Centralises:
  - The canonical policy YAML fixture string (``POLICY_YAML``)
  - ``make_policy_file`` — writes a temp policy YAML and returns its path
  - ``make_structural_engine`` — instantiates a loaded StructuralGatingEngine
  - ``make_mock_semantic_engine`` — creates a mock SemanticGatingEngine with
    configurable verdict, simulated network latency, and optional CPU spin

Import these instead of copy-pasting definitions across checkpoint tests.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

from blackwall.models import ToolCallContext, VerdictDecision
from blackwall.policy.engine import StructuralGatingEngine
from blackwall.policy.models import GateResult
from blackwall.policy.semantic import SemanticGatingEngine

# ---------------------------------------------------------------------------
# Canonical policy YAML
# ---------------------------------------------------------------------------

POLICY_YAML: str = """\
version: "1.0.0"
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
  - ruleId: "block-execute-bash"
    description: "Block execute_bash in all environments"
    enabled: true
    priority: 1
    condition: "toolName == 'execute_bash'"
    action: "BLOCK"
    requireSemanticReview: false
  - ruleId: "allow-read-file"
    description: "Allow read_file without semantic review in sandbox"
    enabled: true
    priority: 10
    condition: "toolName == 'read_file'"
    action: "ALLOW"
    requireSemanticReview: false
semanticGuidelines:
  - "Block any tool call that appears to exfiltrate data or spawn subprocesses."
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
  dbPath: "/tmp/test-pipeline-checkpoint.db"
  walMode: true
  maxConnections: 10
  similarityThreshold: 0.85
  ttlSeconds: 3600
  maxSignatures: 1000
  embeddingDimension: 384
"""


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def make_policy_file(tmp_path: Path, db_name: str = "test_policy.db") -> str:
    """Write ``POLICY_YAML`` to a temp file, substituting the ``dbPath``.

    Args:
        tmp_path: pytest ``tmp_path`` fixture (or any writable directory).
        db_name:  Filename for the SQLite DB embedded in the policy YAML.
                  Defaults to ``"test_policy.db"`` so each caller gets an
                  isolated database without cross-test contamination.

    Returns:
        Absolute path string to the written YAML file.
    """
    db_file = tmp_path / db_name
    policy_content = POLICY_YAML.replace(
        "/tmp/test-pipeline-checkpoint.db",
        str(db_file.absolute()),
    )
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(policy_content)
    return str(policy_file)


def make_structural_engine(policy_yaml_path: str) -> StructuralGatingEngine:
    """Instantiate and load a :class:`StructuralGatingEngine` from *policy_yaml_path*."""
    engine = StructuralGatingEngine()
    engine.load_policy(policy_yaml_path)
    return engine


def make_mock_semantic_engine(
    verdict: VerdictDecision = VerdictDecision.ALLOW,
    latency_ms: float = 0.0,
    cpu_spin_ms: float = 0.0,
) -> AsyncMock:
    """Create a mock :class:`SemanticGatingEngine` that returns a fixed verdict.

    Args:
        verdict:     The :class:`VerdictDecision` the mock will always return.
        latency_ms:  Optional simulated I/O delay (``asyncio.sleep``), in ms.
                     Useful for P99 latency validation tests.
        cpu_spin_ms: Optional busy-wait duration, in ms, executed **before**
                     the async sleep.  Set to ``5.0`` in resource-consumption
                     tests (e.g. ``test_checkpoint_18``) to generate measurable
                     CPU load; leave at ``0.0`` (default) everywhere else.

    Returns:
        A :class:`~unittest.mock.MagicMock` whose ``.evaluate`` attribute is an
        async callable matching the ``SemanticGatingEngine.evaluate`` signature.
    """

    async def _evaluate(
        ctx: ToolCallContext, role: str, *args, **kwargs
    ) -> GateResult:
        if cpu_spin_ms > 0.0:
            deadline = time.perf_counter() + cpu_spin_ms / 1000.0
            while time.perf_counter() < deadline:
                pass  # intentional busy-wait to generate measurable CPU load

        if latency_ms > 0.0:
            await asyncio.sleep(latency_ms / 1000.0)

        return GateResult(
            verdict=verdict,
            reason=f"mock-{verdict.value.lower()}",
            threat_score=0.1 if verdict == VerdictDecision.ALLOW else 0.9,
        )

    mock = MagicMock(spec=SemanticGatingEngine)
    mock.evaluate = _evaluate
    mock.repo = AsyncMock()
    mock.repo.getStatistics = AsyncMock(return_value={"totalSignatures": 0})
    return mock

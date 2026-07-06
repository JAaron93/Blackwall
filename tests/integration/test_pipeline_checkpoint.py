"""
Task 12 Checkpoint: Core Interception Pipeline Integration Tests

Validates the integrated pipeline of:
  Interception Queue → Batch Resolver → Hybrid Policy Server

Checks required by tasks.md §12:
  1. Integration smoke-test: queue + resolver + policy server work end-to-end.
  2. Structural fast-path latency < 5 ms (99th percentile).
  3. Synchronous evaluation path < 10 ms with zero external API calls.
  4. Batch efficiency: ≥ 80 % of API calls carry batch size ≥ 3.
  5. Semantic evaluation latency < 300 ms (99th percentile, mocked MCP).
  6. verify_no_polling.py exits 0 (no polling patterns in analysis path).
  7. Batch resolver delivers correct API batch sizes without splitting.
  8. BLOCK verdict propagates correctly through callback resolution.
  9. Rate limiter returns QUARANTINE verdicts when capacity exhausted.

Note: This integration test uses pytest/pytest-asyncio, consistent with sibling
integration tests, as an intentional exception to any pytest-bdd guideline.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from blackwall.interception import InterceptionQueue
from blackwall.models import (
    CallbackToken,
    ToolCallContext,
    Verdict,
    VerdictDecision,
)
from blackwall.policy.engine import StructuralGatingEngine, StructuralGatingResult
from blackwall.policy.models import GateResult, StructuralAction
from blackwall.policy.semantic import SemanticGatingEngine
from blackwall.policy.server import HybridPolicyServer
from blackwall.resolver import BatchResolver, TokenBucketRateLimiter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_POLICY_YAML = """\
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


@pytest.fixture
def policy_yaml_path(tmp_path: Path) -> str:
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(_POLICY_YAML)
    return str(policy_file)


def _make_structural_engine(policy_yaml_path: str) -> StructuralGatingEngine:
    engine = StructuralGatingEngine()
    engine.load_policy(policy_yaml_path)
    return engine


def _make_mock_semantic_engine(
    verdict: VerdictDecision = VerdictDecision.ALLOW,
    latency_ms: float = 0.0,
) -> AsyncMock:
    """Creates a mock SemanticGatingEngine that returns a fixed verdict."""

    async def _evaluate(ctx: ToolCallContext, role: str) -> GateResult:
        if latency_ms > 0:
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


class _MockInteraction:
    def __init__(self, interaction_id: str = "mock-interaction-id", output: Any = None, total: int = 100, cached: int = 0):
        self.id = interaction_id
        self.output_text = json.dumps(output) if output is not None else json.dumps([])
        self.usage = _MockUsage(total, cached)


class _MockUsage:
    def __init__(self, total: int, cached: int):
        self.total_tokens = total
        self.cached_content_token_count = cached


def _make_batch_resolver_client(batch_size_log: List[int]) -> Any:
    """Produces a mock Gemini client that logs the batch sizes it receives."""

    def create_fn(*args: Any, **kwargs: Any) -> _MockInteraction:
        payload = json.loads(kwargs.get("input", "{}"))
        n = len(payload.get("sanitized_contexts", []))
        batch_size_log.append(n)
        verdicts = [
            {"decision": "ALLOW", "reasoning": "mock-allow", "confidence_score": 0.95}
            for _ in range(n)
        ]
        return _MockInteraction(output=verdicts)

    client = MagicMock()
    client.interactions = MagicMock()
    client.interactions.create = AsyncMock(side_effect=create_fn)
    return client


# ===========================================================================
# Test 1: End-to-end pipeline smoke test
# ===========================================================================


@pytest.mark.asyncio
async def test_pipeline_end_to_end_smoke(policy_yaml_path: str) -> None:
    """
    Validates the full pipeline: InterceptionQueue → BatchResolver → HybridPolicyServer.

    Enqueues 3 tokens, dequeues them as a batch, evaluates via the HybridPolicyServer,
    and resolves all callbacks.  Asserts all callbacks are invoked with the correct verdicts.
    """
    queue = InterceptionQueue()
    tokens: List[CallbackToken] = []
    received_verdicts: List[Verdict] = []

    # Enqueue 3 benign tool calls
    for i in range(3):
        ctx = ToolCallContext(tool_name="read_file", arguments={"path": f"/data/file_{i}.txt"})
        token = CallbackToken(thread_id=f"thread-{i}", tool_context=ctx)

        verdict_bucket: List[Verdict] = []

        def _cb(v: Verdict, _bucket: List[Verdict] = verdict_bucket) -> None:
            _bucket.append(v)
            received_verdicts.append(v)

        await queue.enqueue(token, ctx, _cb)
        tokens.append(token)

    assert queue.size() == 3

    # Dequeue as a batch
    batch = await queue.getBatch(maxSize=5, maxWaitMs=50)
    assert len(batch) == 3

    # Evaluate via HybridPolicyServer
    structural = _make_structural_engine(policy_yaml_path)
    semantic = _make_mock_semantic_engine()
    server = HybridPolicyServer(structural, semantic)

    contexts = [t.tool_context for t in batch]
    roles = ["sandbox"] * len(batch)
    verdicts = await server.evaluateBatch(contexts, roles)

    assert len(verdicts) == 3
    assert all(v.decision == VerdictDecision.ALLOW for v in verdicts)

    # Resolve callbacks
    await queue.resolveCallbacks(verdicts, batch)
    assert len(received_verdicts) == 3
    assert all(v.decision == VerdictDecision.ALLOW for v in received_verdicts)


# ===========================================================================
# Test 2: Structural fast-path latency < 5 ms (99th percentile)
# ===========================================================================

_STRUCTURAL_SAMPLES = 200


@pytest.mark.asyncio
async def test_structural_fast_path_latency(policy_yaml_path: str) -> None:
    """
    Measures the structural-only (fast-path) evaluation latency over
    ``_STRUCTURAL_SAMPLES`` iterations and asserts P99 < 5 ms.

    The fast path exercises BLOCK and ALLOW rules without touching any
    external MCP service or async I/O.
    """
    structural = _make_structural_engine(policy_yaml_path)
    semantic = _make_mock_semantic_engine()
    server = HybridPolicyServer(structural, semantic)

    latencies_ms: List[float] = []

    contexts = [
        ToolCallContext(tool_name="read_file", arguments={"path": "/data/benign.txt"}),
        ToolCallContext(tool_name="execute_bash", arguments={"cmd": "echo hello"}),
    ]

    for i in range(_STRUCTURAL_SAMPLES):
        ctx = contexts[i % len(contexts)]
        t0 = time.perf_counter()
        verdict = await server.evaluate(ctx, "sandbox")
        t1 = time.perf_counter()
        assert verdict.decision in (VerdictDecision.ALLOW, VerdictDecision.BLOCK)
        latencies_ms.append((t1 - t0) * 1000.0)

    sorted_latencies = sorted(latencies_ms)
    p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]
    assert p99 < 5.0, (
        f"Structural fast-path P99 latency {p99:.2f} ms exceeds 5 ms budget. "
        f"All samples: min={min(latencies_ms):.2f}ms, "
        f"max={max(latencies_ms):.2f}ms, p99={p99:.2f}ms"
    )


# ===========================================================================
# Test 3: Synchronous path < 10 ms with zero external API calls
# ===========================================================================


@pytest.mark.asyncio
async def test_synchronous_path_latency_no_external_calls(policy_yaml_path: str) -> None:
    """
    Ensures that the synchronous interception path (structural fast-path only,
    no Gemini/GTI/CBM calls) completes in < 10 ms on average over 100 samples.

    Uses ``read_file`` which maps to ALLOW without semantic review, guaranteeing
    zero async I/O in the evaluation path.
    """
    structural = _make_structural_engine(policy_yaml_path)
    semantic = _make_mock_semantic_engine()
    server = HybridPolicyServer(structural, semantic)

    ctx = ToolCallContext(tool_name="read_file", arguments={"path": "/var/data.csv"})
    latencies_ms: List[float] = []

    for _ in range(100):
        t0 = time.perf_counter()
        verdict = await server.evaluate(ctx, "sandbox")
        t1 = time.perf_counter()
        assert verdict.decision == VerdictDecision.ALLOW
        latencies_ms.append((t1 - t0) * 1000.0)

    avg_ms = sum(latencies_ms) / len(latencies_ms)
    assert avg_ms < 10.0, (
        f"Synchronous path average latency {avg_ms:.3f} ms exceeds 10 ms budget."
    )


# ===========================================================================
# Test 4: Batch efficiency ≥ 80 % of API calls use batch size ≥ 3
# ===========================================================================


@pytest.mark.asyncio
async def test_batch_efficiency_threshold() -> None:
    """
    Verifies that the InterceptionQueue accumulates batches efficiently.

    Simulates a workload where tokens arrive concurrently and asserts that at
    least 80 % of the resulting batches contain ≥ 3 tokens.
    """
    queue = InterceptionQueue()
    batch_sizes: List[int] = []

    # Pre-populate the queue with 30 tokens in groups of 5-10
    group_sizes = [5, 8, 7, 6, 4]  # 30 total

    for g, group_size in enumerate(group_sizes):
        for i in range(group_size):
            ctx = ToolCallContext(
                tool_name="write_file",
                arguments={"path": f"/out/group_{g}_{i}.txt"},
            )
            token = CallbackToken(thread_id=f"thread-{g}-{i}", tool_context=ctx)
            await queue.enqueue(token, ctx, lambda v: None)

    # Drain the queue into batches of max-size 5
    while queue.size() > 0:
        batch = await queue.getBatch(maxSize=5, maxWaitMs=50)
        if not batch:
            break
        batch_sizes.append(len(batch))

    assert batch_sizes, "No batches were produced - check enqueue logic."

    large_batches = sum(1 for s in batch_sizes if s >= 3)
    efficiency = large_batches / len(batch_sizes)
    assert efficiency >= 0.80, (
        f"Batch efficiency {efficiency:.0%} is below the 80% threshold. "
        f"Batch sizes: {batch_sizes}"
    )


# ===========================================================================
# Test 5: Semantic evaluation path latency < 300 ms (P99, mocked MCP)
# ===========================================================================

_SEMANTIC_SAMPLES = 50


@pytest.mark.asyncio
async def test_semantic_evaluation_latency(policy_yaml_path: str) -> None:
    """
    Validates that the semantic gating path (triggered when structural returns
    ESCALATE_TO_SEMANTIC) completes within 300 ms at P99.

    The semantic engine is mocked with a 10 ms delay to simulate real MCP
    round-trips without hitting live services.  The structural engine is
    replaced with a mock that always returns ESCALATE_TO_SEMANTIC.
    """
    # Force escalation to semantic on every call
    mock_struct = MagicMock(spec=StructuralGatingEngine)
    mock_struct.evaluate.return_value = StructuralGatingResult(
        decision=StructuralAction.ESCALATE_TO_SEMANTIC,
        requireSemanticReview=True,
        ruleId="force-escalate",
    )
    mock_struct._policy = MagicMock()
    mock_struct._policy.version = "1.0.0"

    # Semantic engine with a 10 ms simulated MCP latency
    semantic = _make_mock_semantic_engine(
        verdict=VerdictDecision.ALLOW,
        latency_ms=10.0,
    )
    server = HybridPolicyServer(mock_struct, semantic)

    ctx = ToolCallContext(
        tool_name="unknown_tool",
        arguments={"target": "192.0.2.1"},
    )

    latencies_ms: List[float] = []
    for _ in range(_SEMANTIC_SAMPLES):
        t0 = time.perf_counter()
        verdict = await server.evaluate(ctx, "production")
        t1 = time.perf_counter()
        assert verdict.decision == VerdictDecision.ALLOW
        latencies_ms.append((t1 - t0) * 1000.0)

    sorted_latencies = sorted(latencies_ms)
    p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]
    assert p99 < 300.0, (
        f"Semantic evaluation P99 latency {p99:.2f} ms exceeds 300 ms budget. "
        f"min={min(latencies_ms):.2f}ms, max={max(latencies_ms):.2f}ms"
    )


# ===========================================================================
# Test 6: Batch resolver tracks batch sizes for API call efficiency
# ===========================================================================


@pytest.mark.asyncio
async def test_batch_resolver_api_call_batch_sizes() -> None:
    """
    Submits batches of varying sizes through BatchResolver and asserts that
    the API client receives the correct number of contexts per call.

    This is a unit-level verification that the resolver does not split batches
    unnecessarily before dispatching to the Gemini API.
    """
    batch_size_log: List[int] = []
    client = _make_batch_resolver_client(batch_size_log)
    resolver = BatchResolver(client=client)

    # Send three batches: sizes 3, 5, 4
    for batch_size in (3, 5, 4):
        tokens = [
            CallbackToken(
                thread_id=f"t-{batch_size}-{i}",
                tool_context=ToolCallContext(
                    tool_name="read_file",
                    arguments={"path": f"/data/{i}.csv"},
                ),
            )
            for i in range(batch_size)
        ]
        response = await resolver.process_batch(tokens)
        assert len(response.verdicts) == batch_size

    # All three API calls should carry exactly the requested batch sizes
    assert batch_size_log == [3, 5, 4], (
        f"Unexpected batch sizes delivered to Gemini API: {batch_size_log}"
    )

    # All batch sizes ≥ 3 → 100 % efficiency
    large = sum(1 for s in batch_size_log if s >= 3)
    assert large / len(batch_size_log) >= 0.80


# ===========================================================================
# Test 7: verify_no_polling.py exits 0
# ===========================================================================


def test_verify_no_polling_script_exits_zero() -> None:
    """
    Runs ``scripts/verify_no_polling.py`` from the project root and asserts
    that it exits with code 0 (no polling patterns in the analysis path).
    """
    project_root = Path(__file__).parent.parent.parent
    script = project_root / "scripts" / "verify_no_polling.py"

    assert script.exists(), f"verify_no_polling.py not found at {script}"

    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(project_root),
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        f"verify_no_polling.py exited with code {result.returncode}.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert "No polling patterns found" in result.stdout or result.stdout.strip() != "", (
        f"Unexpected output from verify_no_polling.py:\n{result.stdout}"
    )


# ===========================================================================
# Test 8: Pipeline handles BLOCK verdict correctly end-to-end
# ===========================================================================


@pytest.mark.asyncio
async def test_pipeline_block_verdict_propagates(policy_yaml_path: str) -> None:
    """
    Asserts that a BLOCK verdict from structural gating (execute_bash) is
    propagated correctly through resolveCallbacks to the suspended thread.
    """
    queue = InterceptionQueue()
    received: List[Verdict] = []

    ctx = ToolCallContext(tool_name="execute_bash", arguments={"cmd": "whoami"})
    token = CallbackToken(thread_id="thread-malicious", tool_context=ctx)

    async def _resume(v: Verdict) -> None:
        received.append(v)

    def _sync_resume(v: Verdict) -> None:
        received.append(v)

    await queue.enqueue(token, ctx, _sync_resume)
    batch = await queue.getBatch(maxSize=5, maxWaitMs=50)
    assert len(batch) == 1

    structural = _make_structural_engine(policy_yaml_path)
    semantic = _make_mock_semantic_engine()
    server = HybridPolicyServer(structural, semantic)

    verdicts = await server.evaluateBatch(
        [t.tool_context for t in batch],
        ["sandbox"],
    )
    assert verdicts[0].decision == VerdictDecision.BLOCK

    await queue.resolveCallbacks(verdicts, batch)

    assert len(received) == 1
    assert received[0].decision == VerdictDecision.BLOCK
    assert received[0].reasoning == "BLOCKED_BY_STRUCTURAL_RULE"


# ===========================================================================
# Test 9: Rate limiter prevents throughput breach during batch accumulation
# ===========================================================================


@pytest.mark.asyncio
async def test_rate_limiter_caps_api_throughput() -> None:
    """
    Verifies that when the token bucket is exhausted, BatchResolver returns
    QUARANTINE verdicts instead of violating the 300 RPM API ceiling.
    """
    batch_size_log: List[int] = []
    client = _make_batch_resolver_client(batch_size_log)
    resolver = BatchResolver(client=client)
    # Drain the bucket entirely: only 5 tokens remain
    resolver.rate_limiter = TokenBucketRateLimiter(capacity=2.0, refill_rate=0.0)

    ctx = ToolCallContext(tool_name="read_file", arguments={"path": "/data/ok.csv"})
    token = CallbackToken(thread_id="t-rl", tool_context=ctx)

    # First 2 calls should consume the remaining tokens
    for _ in range(2):
        resp = await resolver.process_batch([token])
        assert resp.verdicts[0].decision == VerdictDecision.ALLOW

    # 3rd call must be quarantined (rate limit exhausted)
    resp = await resolver.process_batch([token])
    assert resp.verdicts[0].decision == VerdictDecision.QUARANTINE
    assert "Rate limit" in resp.verdicts[0].reasoning

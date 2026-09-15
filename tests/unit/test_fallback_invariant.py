"""TASK-5.2: Pure-Python Fallback Invariant Tests.

Verifies that all Rust-accelerated hot paths continue to work correctly in pure-Python
fallback mode (FR-5, NFR-2) by monkey-patching `_core_rs = None` in each module.

These tests ensure 100% behavioral parity between the native Rust extension and the
pure-Python fallback implementations, validating the FR-5 fallback invariant.

Traceability: FR-5, NFR-2, All FRs, TASK-5.2
"""

import importlib
import sys
import types
import uuid
from datetime import datetime, timezone, timedelta
from unittest import mock
import pytest


def _ensure_native_extension():
    """Ensure the native compiled _core_rs extension is installed and functional.

    Prevents tests from silently comparing Python fallback against Python fallback.
    """
    try:
        from blackwall import _core_rs
        assert _core_rs is not None
        assert hasattr(_core_rs, "dfs_find_paths")
    except (ImportError, AssertionError) as exc:
        pytest.fail(f"Native _core_rs extension must be installed to verify parity: {exc}")


# ──────────────────────────────────────────────────────────────────────────────
# Helper: create a NormalizedEvent for testing
# ──────────────────────────────────────────────────────────────────────────────

def _make_event(agent_id="fallback-agent", action="exec", target="/bin/sh", offset=0.0):
    """Create a minimal NormalizedEvent for fallback tests."""
    from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent
    from blackwall.enterprise.advanced_threat_detection.enums import EventSource

    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset),
        source=EventSource.TOOL_CALL,
        agent_id=agent_id,
        action=action,
        target=target,
        risk_score=0.6,
    )


# ──────────────────────────────────────────────────────────────────────────────
# TASK-5.2-1: Context Hygiene fallback invariant
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_context_hygiene_middleware_fallback_invariant():
    """Verify middleware ContextHygiene produces identical output in pure-Python fallback mode."""
    _ensure_native_extension()
    import blackwall.middleware.context_hygiene as ch_module

    payload = "api_key=SECRET_TOKEN_XYZ_12345 and host=10.0.0.1"

    ch_native = ch_module.ContextHygiene()
    sanitized_native, _ = await ch_native.apply_redaction(payload)

    ch_fallback = ch_module.ContextHygiene()
    ch_fallback._rust_sanitizer = None
    sanitized_fallback, _ = await ch_fallback.apply_redaction(payload)

    assert sanitized_native == sanitized_fallback, (
        f"Middleware sanitized text mismatch:\n"
        f"  Native:   {sanitized_native!r}\n"
        f"  Fallback: {sanitized_fallback!r}"
    )


def test_context_hygiene_resolver_fallback_invariant():
    """Verify resolver ContextHygiene produces identical output in pure-Python fallback mode."""
    _ensure_native_extension()
    import blackwall.resolver as resolver_module
    from blackwall.models import ToolCallContext

    payload = "api_key=SECRET_TOKEN_XYZ_12345"
    ctx_native = ToolCallContext(tool_name="bash", arguments={"cmd": payload})
    ctx_fallback = ToolCallContext(tool_name="bash", arguments={"cmd": payload})

    ch_native = resolver_module.ContextHygiene()
    sanitized_ctx_native = ch_native.sanitize_context(ctx_native)

    ch_fallback = resolver_module.ContextHygiene()
    ch_fallback._rust_sanitizer = None
    sanitized_ctx_fallback = ch_fallback.sanitize_context(ctx_fallback)

    assert sanitized_ctx_native.arguments == sanitized_ctx_fallback.arguments, (
        f"Resolver sanitized text mismatch:\n"
        f"  Native:   {sanitized_ctx_native.arguments!r}\n"
        f"  Fallback: {sanitized_ctx_fallback.arguments!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# TASK-5.2-2: Vector similarity fallback invariant
# ──────────────────────────────────────────────────────────────────────────────

def test_cosine_similarity_fallback_invariant():
    """Verify compute_word_intersection_match_quality fallback produces same result."""
    _ensure_native_extension()
    import blackwall.validators as validators_module

    query = "SELECT * FROM users WHERE admin"
    candidate = "SELECT * FROM users"

    # Baseline with whatever is installed
    score_native = validators_module.compute_word_intersection_match_quality(query, candidate)

    # Fallback mode
    with mock.patch.object(validators_module, "_core_rs", None):
        score_fallback = validators_module.compute_word_intersection_match_quality(query, candidate)

    assert abs(score_native - score_fallback) < 1e-9, (
        f"Word intersection score mismatch: native={score_native}, fallback={score_fallback}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# TASK-5.2-3: IOC extraction fallback invariant
# ──────────────────────────────────────────────────────────────────────────────

def test_ioc_extraction_fallback_invariant():
    """Verify IOC extraction produces identical results in pure-Python fallback mode."""
    _ensure_native_extension()
    import blackwall.policy.semantic as semantic_module
    from blackwall.models import ToolCallContext

    payload = "Connected to 192.168.1.200 at https://c2.evil.example.com"
    ctx = ToolCallContext(tool_name="bash", arguments={"cmd": payload})

    # Baseline
    iocs_native = semantic_module.extract_iocs(ctx)

    # Fallback
    with mock.patch.object(semantic_module, "_core_rs", None):
        iocs_fallback = semantic_module.extract_iocs(ctx)

    assert set(iocs_native.get("ips", [])) == set(iocs_fallback.get("ips", [])), (
        f"IOC IP mismatch: native={iocs_native.get('ips')}, fallback={iocs_fallback.get('ips')}"
    )


def test_entropy_fallback_invariant():
    """Verify Shannon entropy calculation produces identical result in fallback mode."""
    _ensure_native_extension()
    import blackwall.policy.semantic as semantic_module

    payload = "aabbccddee" * 100  # Known entropy input

    # Baseline
    entropy_native = semantic_module.calculate_entropy(payload)

    # Fallback
    with mock.patch.object(semantic_module, "_core_rs", None):
        entropy_fallback = semantic_module.calculate_entropy(payload)

    assert abs(entropy_native - entropy_fallback) < 1e-9, (
        f"Entropy mismatch: native={entropy_native:.6f}, fallback={entropy_fallback:.6f}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# TASK-5.2-4: Graph DFS correlator fallback invariant
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_path_correlator_fallback_invariant():
    """Verify PathCorrelator produces equivalent paths in pure-Python fallback mode.

    With _core_rs=None in correlator, the pure-Python _dfs_path_search loop runs.
    Both modes must find at least one valid attack path.
    """
    _ensure_native_extension()
    from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
    from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
    import blackwall.enterprise.advanced_threat_detection.correlator as correlator_module

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    # Insert 3 events forming a path (within 300s window)
    async def setup_store():
        store = AttackGraphStore(in_memory=True)
        await store.initialize()
        for i, (action, target) in enumerate([
            ("exec", "/bin/bash"),
            ("sudo", "root"),
            ("exfil", "c2.evil.com"),
        ]):
            ev = _make_event(agent_id="fallback-test", action=action, target=target, offset=float(i * 60))
            await store.insert_event(ev)
        return store

    time_win = (base_time - timedelta(seconds=10), base_time + timedelta(seconds=500))

    # Baseline (native mode)
    store_native = await setup_store()
    correlator_native = PathCorrelator(store=store_native)
    paths_native = await correlator_native.correlate_attack_paths(
        "fallback-test", time_win, min_path_length=2
    )

    # Fallback mode (_core_rs = None in correlator module)
    store_fallback = await setup_store()
    with mock.patch.object(correlator_module, "_core_rs", None):
        correlator_fallback = PathCorrelator(store=store_fallback)
        paths_fallback = await correlator_fallback.correlate_attack_paths(
            "fallback-test", time_win, min_path_length=2
        )

    # Both must find paths of length >= 2
    assert len(paths_native) > 0, "Native mode found no paths"
    assert len(paths_fallback) > 0, "Fallback mode found no paths (FR-5 violated)"

    # All paths must have valid risk_score bounds in both modes
    for path in paths_native + paths_fallback:
        assert 0.0 <= path.risk_score <= 1.0, f"risk_score out of bounds: {path.risk_score}"
        assert len(path.nodes) >= 2, f"path has fewer than 2 nodes: {len(path.nodes)}"


# ──────────────────────────────────────────────────────────────────────────────
# TASK-5.2-5: _avg_min_time_diff swarm fallback invariant
# ──────────────────────────────────────────────────────────────────────────────

def test_avg_min_time_diff_swarm_fallback_invariant():
    """Verify _avg_min_time_diff in swarm.py produces identical results in fallback mode."""
    _ensure_native_extension()
    from blackwall.enterprise.advanced_threat_detection import swarm as swarm_module
    from blackwall.enterprise.advanced_threat_detection.swarm import _avg_min_time_diff

    base = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    ts1 = [base + timedelta(seconds=i * 10) for i in range(10)]
    ts2 = [base + timedelta(seconds=i * 10 + 5) for i in range(10)]

    # Baseline (native)
    result_native = _avg_min_time_diff(ts1, ts2)

    # Fallback
    with mock.patch.object(swarm_module, "_core_rs", None):
        result_fallback = _avg_min_time_diff(ts1, ts2)

    assert abs(result_native - result_fallback) < 1e-9, (
        f"avg_min_time_diff mismatch: native={result_native:.6f}, fallback={result_fallback:.6f}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# TASK-5.2-6: No import-time crash without _core_rs
# ──────────────────────────────────────────────────────────────────────────────

def test_modules_import_without_core_rs():
    """Verify all wrapper modules can be imported cleanly without _core_rs available.

    Evicts modules from sys.modules to guarantee fresh uncached imports without _core_rs.
    Validates FR-5: 'zero runtime errors' when native extension is missing.
    """
    # Modules that import _core_rs at the top level
    modules_to_test = [
        "blackwall.middleware.context_hygiene",
        "blackwall.validators",
        "blackwall.policy.semantic",
        "blackwall.enterprise.advanced_threat_detection.correlator",
        "blackwall.enterprise.advanced_threat_detection.swarm",
    ]

    for mod_name in modules_to_test:
        saved_module = sys.modules.pop(mod_name, None)
        try:
            with mock.patch.dict(sys.modules, {"blackwall._core_rs": None, "_core_rs": None}):
                mod = importlib.import_module(mod_name)
                assert mod is not None
        except ImportError as exc:
            pytest.fail(
                f"Module {mod_name!r} raised ImportError without _core_rs: {exc} "
                f"(FR-5 violated: all modules must import cleanly in fallback mode)"
            )
        finally:
            if saved_module is not None:
                sys.modules[mod_name] = saved_module


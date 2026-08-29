"""Unit tests and benchmarks for Rust-accelerated similarity scoring and candidate isolation."""

import array
import math
import time
import pytest
from blackwall import _core_rs


def test_cosine_similarity_accuracy():
    """Verify mathematical accuracy of cosine similarity against pure-Python reference."""
    v1 = [1.0, 2.0, 3.0, 4.0, 5.0]
    v2 = [5.0, 4.0, 3.0, 2.0, 1.0]

    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))
    expected = dot / (norm1 * norm2)

    actual = _core_rs.cosine_similarity(v1, v2)
    assert actual == pytest.approx(expected, rel=1e-5)


def test_cosine_similarity_dimension_mismatch():
    """Verify ValueError is raised if vector dimensions differ."""
    with pytest.raises(ValueError, match="same dimension"):
        _core_rs.cosine_similarity([1.0, 2.0], [1.0, 2.0, 3.0])


def test_cosine_similarity_empty():
    """Verify ValueError is raised for empty vectors."""
    with pytest.raises(ValueError, match="must not be empty"):
        _core_rs.cosine_similarity([], [])


def test_batch_cosine_similarity_query_dimension_validation():
    """Verify ValueError is raised when query vector does not match expected dimension."""
    query = [1.0] * 512
    with pytest.raises(ValueError, match="Query vector has incorrect dimension 512, expected 768"):
        _core_rs.batch_cosine_similarity(query, [], 768, 0.85)


def test_batch_cosine_similarity_malformed_candidate_isolation():
    """Verify corrupted candidate vectors are isolated without aborting the batch."""
    q = [1.0] * 768
    valid_bytes = array.array("f", q).tobytes()
    bad_dim_bytes = array.array("f", [1.0] * 384).tobytes()
    corrupted_bytes = b"\x01\x02\x03"  # Not a multiple of 4 bytes

    candidates = [
        ("sig-valid-1", valid_bytes),
        ("sig-bad-dim", bad_dim_bytes),
        ("sig-valid-2", valid_bytes),
        ("sig-corrupted", corrupted_bytes),
    ]

    matches, exclusions = _core_rs.batch_cosine_similarity(q, candidates, 768, 0.85)

    assert len(matches) == 2
    matched_ids = [m[0] for m in matches]
    assert "sig-valid-1" in matched_ids
    assert "sig-valid-2" in matched_ids
    assert all(m[1] == pytest.approx(1.0, rel=1e-5) for m in matches)

    assert len(exclusions) == 2
    excluded_map = dict(exclusions)
    assert "sig-bad-dim" in excluded_map
    assert "incorrect vector dimension 384" in excluded_map["sig-bad-dim"]
    assert "sig-corrupted" in excluded_map
    assert "error decoding vector" in excluded_map["sig-corrupted"]


def test_word_intersection_match_quality_parity():
    """Verify word-level intersection match quality parity with Python reference."""
    q = "SQL injection attempt with SELECT and UNION"
    c = "SELECT * FROM users UNION SELECT null"

    # Reference Python
    import re
    q_words = set(re.findall(r"\w+", q.lower()))
    c_words = set(re.findall(r"\w+", c.lower()))
    expected = len(q_words & c_words) / min(len(q_words), len(c_words))

    actual = _core_rs.compute_word_intersection_match_quality(q, c)
    assert actual == pytest.approx(expected, rel=1e-5)


def test_batch_cosine_similarity_latency_benchmark():
    """Verify 768-dim vector batch search over 1,000 candidate vectors executes in under 5ms."""
    q = [0.1 * (i % 10) for i in range(768)]
    q_norm = math.sqrt(sum(x * x for x in q))
    q_unit = [x / q_norm for x in q]

    cand_bytes = array.array("f", q_unit).tobytes()
    candidates = [(f"sig-{i}", cand_bytes) for i in range(1000)]

    # Warmup
    _core_rs.batch_cosine_similarity(q_unit, candidates[:10], 768, 0.85)

    start = time.perf_counter()
    matches, exclusions = _core_rs.batch_cosine_similarity(q_unit, candidates, 768, 0.85)
    elapsed_sec = time.perf_counter() - start

    assert len(matches) == 1000
    assert len(exclusions) == 0
    # Average per-candidate latency < 500 microseconds (SLA: < 20 microseconds per 100 vectors)
    per_cand_us = (elapsed_sec * 1_000_000) / 1000
    assert per_cand_us < 500.0, f"Batch similarity took too long: {per_cand_us:.2f}us/candidate"

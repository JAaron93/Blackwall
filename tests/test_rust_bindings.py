"""Unit tests for Blackwall Rust extension bindings and fallback verification."""

from urllib.parse import urlparse

import pytest


def test_rust_module_import():
    """Verify that the compiled Rust extension _core_rs is importable and exposes version."""
    from blackwall import _core_rs
    import blackwall

    assert hasattr(_core_rs, "__version__")
    assert _core_rs.__version__ == "0.1.0"
    assert blackwall._core_rs is not None
    assert blackwall._core_rs.__version__ == "0.1.0"


def test_rust_similarity_bindings():
    """Verify similarity scoring functions in _core_rs."""
    from blackwall import _core_rs

    # Cosine similarity
    v1 = [1.0, 0.0, 0.0]
    v2 = [1.0, 0.0, 0.0]
    assert _core_rs.cosine_similarity(v1, v2) == pytest.approx(1.0)

    # Word intersection match quality
    score = _core_rs.compute_word_intersection_match_quality(
        "select users", "select users where id = 1"
    )
    assert score == pytest.approx(1.0)

    # Batch cosine similarity
    import array
    q = [1.0] * 768
    cand_bytes = array.array("f", q).tobytes()
    matches, exclusions = _core_rs.batch_cosine_similarity(q, [("sig-1", cand_bytes)], 768, 0.85)
    assert len(matches) == 1
    assert matches[0][0] == "sig-1"
    assert len(exclusions) == 0


def test_rust_iocs_and_entropy_bindings():
    """Verify IOC extraction and entropy functions in _core_rs."""
    from blackwall import _core_rs

    # Entropy
    h = _core_rs.calculate_entropy("abcd")
    assert h == pytest.approx(2.0)
    assert _core_rs.calculate_entropy("") == 0.0

    # IOCs
    iocs = _core_rs.extract_iocs(["192.168.1.1", "https://example.com", "d41d8cd98f00b204e9800998ecf8427e"])
    assert "192.168.1.1" in iocs["ips"]
    assert "example.com" in {urlparse(u).hostname for u in iocs["urls"] if urlparse(u).hostname}
def test_pure_python_fallbacks_when_core_rs_unavailable(monkeypatch):
    """Verify that Python wrappers gracefully fall back to pure-Python implementations when _core_rs is None."""
    import blackwall.validators as val
    import blackwall.policy.semantic as sem
    import blackwall.db.repository as repo

    with monkeypatch.context() as m:
        m.setattr(val, "_core_rs", None)
        m.setattr(sem, "_core_rs", None)
        m.setattr(repo, "_core_rs", None)

        # Validators fallback
        assert val.compute_word_intersection_match_quality("select users", "select users where id = 1") == pytest.approx(1.0)
        assert val.compute_cosine_similarity([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)

        # Semantic entropy fallback
        assert sem.calculate_entropy("abcd") == pytest.approx(2.0)
        assert sem.calculate_entropy("") == 0.0

        # Semantic IOCs fallback
        from blackwall.models import ToolCallContext
        ctx = ToolCallContext(
            tool_name="test_tool",
            arguments={"host": "192.168.1.1", "url": "https://evil.com", "hash": "d41d8cd98f00b204e9800998ecf8427e"}
        )
        iocs = sem.extract_iocs(ctx)
        assert "192.168.1.1" in iocs["ips"]
        assert "https://evil.com" in iocs["urls"]
        assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["hashes"]





"""Tests the raw-dictionary threat-intel cache API over the unified
threat_intel_cache table."""

import json
import sqlite3

import pytest

from blackwall.db.repository import SQLiteThreatRepository


def _tables(path: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_dict_api_roundtrips_through_unified_table(tmp_path):
    repo = SQLiteThreatRepository(db_path=str(tmp_path / "bw2.db"))
    await repo.initialize()

    await repo.cache_threat_intel_response(
        "8.8.8.8", "ip_address", {"provider_name": "otx", "is_malicious": False}
    )
    cached = await repo.get_cached_threat_intel_response("8.8.8.8", "ip_address")
    # The payload is enriched with canonical keys for typed readability,
    # so assert on the caller-supplied subset rather than exact equality.
    assert cached["provider_name"] == "otx"
    assert cached["is_malicious"] is False

    conn = sqlite3.connect(str(tmp_path / "bw2.db"))
    try:
        row = conn.execute(
            "SELECT provider, is_malicious FROM threat_intel_cache WHERE indicator = ?",
            ("8.8.8.8",),
        ).fetchone()
    finally:
        conn.close()
    assert row == ("otx", 0)


@pytest.mark.asyncio
async def test_raw_written_row_is_readable_by_typed_lookup(tmp_path):
    """Regression (Greptile P1): a raw-dictionary row must not become a
    typed-lookup cache miss — the enriched payload must validate as
    ThreatIntelResponse so both readers share the unified table."""
    repo = SQLiteThreatRepository(db_path=str(tmp_path / "bw3.db"))
    await repo.initialize()

    await repo.cache_threat_intel_response(
        "8.8.8.8", "IP_ADDRESS", {"score": 42}  # minimal dict, no canonical keys
    )

    typed = await repo.get_cached_threat_intel("8.8.8.8", "IP_ADDRESS")
    assert typed is not None, "typed lookup must read raw-written rows"
    assert typed.cached is True
    assert typed.is_malicious is False
    assert typed.indicator == "8.8.8.8"
    assert typed.indicator_type.value == "IPV4"

    # The raw-dictionary reader still returns the enriched payload.
    raw = await repo.get_cached_threat_intel_response("8.8.8.8", "IP_ADDRESS")
    assert raw is not None
    assert raw["score"] == 42
    assert raw["indicator_type"] == "IPV4"

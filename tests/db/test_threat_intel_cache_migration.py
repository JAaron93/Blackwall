"""Tests the raw-dictionary threat-intel cache API over the unified
threat_intel_cache table (GTI→TI janitorial rename)."""

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
    assert cached == {"provider_name": "otx", "is_malicious": False}

    conn = sqlite3.connect(str(tmp_path / "bw2.db"))
    try:
        row = conn.execute(
            "SELECT provider, is_malicious FROM threat_intel_cache WHERE indicator = ?",
            ("8.8.8.8",),
        ).fetchone()
    finally:
        conn.close()
    assert row == ("otx", 0)

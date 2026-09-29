"""Tests legacy gti_cache absorption into the unified threat_intel_cache
(GTI→TI janitorial rename, commit 1)."""

import json
import sqlite3
import time

import pytest

from blackwall.db.repository import SQLiteThreatRepository

LEGACY_SCHEMA = """
CREATE TABLE gti_cache (
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    response_data TEXT NOT NULL,
    cached_at INTEGER NOT NULL,
    PRIMARY KEY (indicator, indicator_type)
);
"""


def _make_legacy_db(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute(LEGACY_SCHEMA)
    now = int(time.time())
    conn.execute(
        "INSERT INTO gti_cache VALUES (?, ?, ?, ?)",
        (
            "1.2.3.4",
            "ip_address",
            json.dumps(
                {"provider_name": "otx", "is_malicious": True, "risk_score": 0.9}
            ),
            now,
        ),
    )
    conn.execute(
        "INSERT INTO gti_cache VALUES (?, ?, ?, ?)",
        ("evil.example.com", "domain", json.dumps({"score": 42}), now),
    )
    conn.commit()
    conn.close()


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
async def test_legacy_gti_cache_absorbed_and_dropped(tmp_path):
    db = str(tmp_path / "bw.db")
    _make_legacy_db(db)

    repo = SQLiteThreatRepository(db_path=db)
    await repo.initialize()

    ip_row = await repo.get_cached_threat_intel_response("1.2.3.4", "ip_address")
    assert ip_row is not None
    assert ip_row["risk_score"] == 0.9

    # Cache TTL contract: malicious verdicts expire in 6h, benign in 24h.
    conn = sqlite3.connect(db)
    try:
        rows = dict(
            conn.execute(
                "SELECT indicator, expires_at - created_at FROM threat_intel_cache"
            ).fetchall()
        )
    finally:
        conn.close()
    assert rows["1.2.3.4"] == 21600.0  # malicious
    assert rows["evil.example.com"] == 86400.0  # benign/unknown

    domain_row = await repo.get_cached_threat_intel_response(
        "evil.example.com", "domain"
    )
    assert domain_row == {"score": 42}

    tables = _tables(db)
    assert "gti_cache" not in tables
    assert "threat_intel_cache" in tables


@pytest.mark.asyncio
async def test_absorption_is_idempotent(tmp_path):
    db = str(tmp_path / "bw.db")
    _make_legacy_db(db)

    repo = SQLiteThreatRepository(db_path=db)
    await repo.initialize()
    await repo.initialize()  # second open: legacy table already gone, no error

    conn = sqlite3.connect(db)
    try:
        count = conn.execute("SELECT COUNT(*) FROM threat_intel_cache").fetchone()[0]
    finally:
        conn.close()
    assert count == 2


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

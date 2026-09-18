"""Regression tests for failed connection-pool initialization (pool thread leak).

Covers the hang observed in
``tests/unit/gateway/test_cli.py::TestBlackwallCLI::test_status_command_corrupted_database_reports_inaccessible``:
initializing ``AsyncConnectionPool`` against a corrupt SQLite file raised
``sqlite3.DatabaseError`` after ``aiosqlite`` had already spawned its
(non-daemon) worker thread. ``close()`` early-returned on the uninitialized
pool, leaking the thread and blocking interpreter exit forever in
``threading._shutdown`` — the pytest process never terminated.

Invariants under test:
- A failed ``initialize()`` must close partially-created connections.
- ``close()`` must drain the pool even when initialization never completed.
- No new live threads may survive a failed init + close cycle.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from blackwall.db.pool import AsyncConnectionPool
from blackwall.db.repository import SQLiteThreatRepository


def _live_extra_threads(before: set[str]) -> list[threading.Thread]:
    return [
        t
        for t in threading.enumerate()
        if t.name not in before and t.is_alive()
    ]


class TestPoolInitFailure:
    """Failed pool init must not leak worker threads."""

    @pytest.mark.asyncio
    async def test_failed_initialize_closes_partial_connections(
        self, tmp_path: Path
    ) -> None:
        corrupt = tmp_path / "corrupt.db"
        corrupt.write_text("NOT A VALID SQLITE DATABASE FILE")

        before = {t.name for t in threading.enumerate()}
        pool = AsyncConnectionPool(str(corrupt), max_connections=3)
        with pytest.raises(Exception):
            await pool.initialize()
        await pool.close()

        leaked = _live_extra_threads(before)
        assert leaked == [], (
            f"Failed init leaked {len(leaked)} thread(s): "
            f"{[(t.name, t.daemon) for t in leaked]}"
        )

    @pytest.mark.asyncio
    async def test_repository_close_after_failed_init_leaks_no_threads(
        self, tmp_path: Path
    ) -> None:
        corrupt = tmp_path / "corrupt.db"
        corrupt.write_text("NOT A VALID SQLITE DATABASE FILE")

        before = {t.name for t in threading.enumerate()}
        repo = SQLiteThreatRepository(db_path=str(corrupt))
        with pytest.raises(Exception):
            await repo.initialize()
        await repo.close()

        leaked = _live_extra_threads(before)
        assert leaked == [], (
            f"Failed repo init leaked {len(leaked)} thread(s): "
            f"{[(t.name, t.daemon) for t in leaked]}"
        )

    @pytest.mark.asyncio
    async def test_successful_init_close_cycle_leaks_no_threads(
        self, tmp_path: Path
    ) -> None:
        """Sanity: the happy path already cleans up; guard against regressions."""
        db = tmp_path / "healthy.db"

        before = {t.name for t in threading.enumerate()}
        pool = AsyncConnectionPool(str(db), max_connections=2)
        await pool.initialize()
        await pool.close()

        leaked = _live_extra_threads(before)
        assert leaked == [], (
            f"Healthy init/close leaked {len(leaked)} thread(s): "
            f"{[(t.name, t.daemon) for t in leaked]}"
        )

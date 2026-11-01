"""Property-based tests for resource cleanup lifecycle paths.

Covers the AuditHookManager SQLite connection release and the resolvers'
``_schedule_task`` coroutine-closing contract across generated inputs.
"""

import asyncio
import gc
import tempfile
import warnings
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.audit.manager import AuditHookManager
from blackwall.resolver import BatchResolver
from blackwall.sync_resolver import SyncResolver

# Per .agents/rules/testing_and_hygiene.md #17: no bare st.text(min_size=1)
# for validated string inputs; use regex-bound or stripped strategies.
executable_st = st.from_regex(r"/[a-zA-Z0-9_./-]{1,40}", fullmatch=True)
payload_st = st.one_of(st.integers(), st.booleans(), executable_st)


# Property 1: stop() releases the thread-local connection for any blocked event
@settings(max_examples=100)
@given(executable=executable_st)
def test_property_stop_releases_connection(executable):
    with tempfile.TemporaryDirectory() as td:
        mgr = AuditHookManager(db_path=str(Path(td) / "prop.db"))
        mgr.start()
        with pytest.raises(PermissionError):
            mgr.handle_event("subprocess.Popen", (executable, []))
        assert getattr(mgr._local, "conn", None) is not None
        mgr.stop()
        assert not hasattr(mgr._local, "conn")


# Property 2: _schedule_task without a running loop closes any coroutine
@settings(max_examples=100)
@given(payload=payload_st)
def test_property_schedule_task_without_loop_closes_coroutine(payload):
    async def _work():
        return payload

    for resolver_cls in (BatchResolver, SyncResolver):
        resolver = resolver_cls(client=MagicMock())
        coro = _work()
        resolver._schedule_task(coro)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            del coro
            gc.collect()
        leaked = [str(w.message) for w in caught if issubclass(w.category, RuntimeWarning)]
        assert not leaked, f"{resolver_cls.__name__} leaked: {leaked}"


# Property 3: with a running loop the scheduled task executes and yields the
# payload (async property per rule #27: sync _run() helper, deadline=None)
@settings(max_examples=100, deadline=None)
@given(payload=payload_st)
def test_property_schedule_task_with_loop_executes(payload):
    async def _main():
        resolver = BatchResolver(client=MagicMock())

        async def _work():
            return payload

        resolver._schedule_task(_work())
        await asyncio.sleep(0)
        tasks = list(resolver._background_tasks)
        assert len(tasks) == 1
        assert tasks[0].done()
        assert tasks[0].result() == payload

    asyncio.run(_main())

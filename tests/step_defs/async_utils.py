"""Async helper utilities for pytest-bdd step definitions."""

import asyncio
from typing import Any, Coroutine


def run_async(coro: Coroutine[Any, Any, Any]) -> Any:
    """Execute asynchronous coroutine synchronously in pytest-bdd step definitions."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

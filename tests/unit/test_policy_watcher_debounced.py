"""Unit tests for modernized PolicyWatcher with debouncing and context manager."""

import os
import time
from unittest.mock import MagicMock
import pytest
from blackwall.policy.watcher import PolicyFileHandler, PolicyWatcher


def test_policy_file_handler_debouncing():
    """Verify rapid consecutive events coalesce into a single callback execution."""
    callback = MagicMock()
    file_path = "/tmp/test_policy.yaml"
    handler = PolicyFileHandler(file_path, callback, debounce_interval=0.1)

    mock_event = MagicMock()
    mock_event.is_directory = False
    mock_event.src_path = file_path
    mock_event.dest_path = None

    # Trigger 5 rapid events within the debounce window
    for _ in range(5):
        handler.on_modified(mock_event)
        time.sleep(0.01)

    assert callback.call_count == 1
    handler.cancel_pending()


def test_policy_file_handler_retries_on_failure_and_does_not_drop_subsequent_event():
    """Verify an event within 50ms is NOT dropped if the initial callback failed on incomplete YAML."""
    call_attempts = []

    def failing_then_succeeding_callback(path: str) -> None:
        call_attempts.append(path)
        if len(call_attempts) == 1:
            raise ValueError("Incomplete YAML during in-progress write")

    file_path = "/tmp/test_policy.yaml"
    handler = PolicyFileHandler(file_path, failing_then_succeeding_callback, debounce_interval=0.1)

    mock_event = MagicMock()
    mock_event.is_directory = False
    mock_event.src_path = file_path
    mock_event.dest_path = None

    # First event fails (e.g. incomplete YAML)
    handler.on_modified(mock_event)
    assert len(call_attempts) == 1

    # Second event arrives 20ms later (well within 100ms debounce window)
    time.sleep(0.02)
    handler.on_modified(mock_event)

    # Must NOT be dropped: second event executes immediately and succeeds
    assert len(call_attempts) == 2
    handler.cancel_pending()


def test_policy_file_handler_trailing_retry_on_failure():
    """Verify a trailing retry automatically executes if an event fails and no further events arrive."""
    call_attempts = []

    def failing_then_succeeding_callback(path: str) -> None:
        call_attempts.append(path)
        if len(call_attempts) == 1:
            raise ValueError("Incomplete YAML during in-progress write")

    file_path = "/tmp/test_policy.yaml"
    handler = PolicyFileHandler(file_path, failing_then_succeeding_callback, debounce_interval=0.05)

    mock_event = MagicMock()
    mock_event.is_directory = False
    mock_event.src_path = file_path
    mock_event.dest_path = None

    # First event fails
    handler.on_modified(mock_event)
    assert len(call_attempts) == 1

    # Wait for trailing retry timer (0.05s interval + margin)
    time.sleep(0.1)

    # Trailing retry must have fired
    assert len(call_attempts) == 2
    handler.cancel_pending()


def test_policy_watcher_context_manager(tmp_path):
    """Verify PolicyWatcher works as a context manager starting and stopping the observer."""
    policy_file = str(tmp_path / "policy.yaml")
    with open(policy_file, "w") as f:
        f.write("rules: []\n")

    callback = MagicMock()
    watcher = PolicyWatcher(policy_file, callback)

    assert watcher.observer is None
    with watcher:
        assert watcher.observer is not None
        assert watcher.observer.is_alive()

    assert watcher.observer is None


def test_policy_watcher_stop_waits_for_active_timer():
    """Verify stop/cancel_pending waits for any running reload timer to finish before returning."""
    import threading

    reload_started = threading.Event()
    reload_finished = threading.Event()

    def slow_reload(path: str) -> None:
        reload_started.set()
        time.sleep(0.05)
        reload_finished.set()

    file_path = "/tmp/test_slow_policy.yaml"
    handler = PolicyFileHandler(file_path, slow_reload, debounce_interval=0.01)

    # Schedule a trailing reload
    handler._schedule_trailing_reload()

    # Wait until the timer starts executing the reload callback
    assert reload_started.wait(timeout=1.0) is True

    # Call cancel_pending while slow_reload is actively executing
    handler.cancel_pending()

    # Must wait: reload_finished must be set when cancel_pending returns
    assert reload_finished.is_set() is True

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

import os
import time
from typing import Any, Callable, Optional
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
import structlog

logger = structlog.get_logger("blackwall.policy")


class PolicyFileHandler(FileSystemEventHandler):
    """File system event handler that listens for modifications to the policy YAML file with debouncing."""

    def __init__(
        self,
        file_path: str,
        reload_callback: Callable[[str], None],
        debounce_interval: float = 0.05,
    ) -> None:
        super().__init__()
        self.file_path = os.path.realpath(file_path)
        self.reload_callback = reload_callback
        self.debounce_interval = float(debounce_interval)
        self._last_reload_time: float = 0.0

    def _handle_event(self, event: Any, event_type: str) -> None:
        if getattr(event, "is_directory", False):
            return

        dest = getattr(event, "dest_path", None)
        src = getattr(event, "src_path", None)
        target = os.path.realpath(dest if dest else src)
        if target != self.file_path:
            return

        now = time.time()
        if now - self._last_reload_time < self.debounce_interval:
            logger.debug(
                "Suppressing duplicate policy reload within debounce window",
                file_path=self.file_path,
            )
            return
        self._last_reload_time = now

        logger.info(
            f"Policy file {event_type} detected on disk. Triggering hot-reload...",
            file_path=self.file_path,
        )
        try:
            self.reload_callback(self.file_path)
        except Exception as e:
            logger.error(
                "Failed to hot-reload policy file; retaining previous valid policy.",
                error=str(e),
                file_path=self.file_path,
            )

    def on_modified(self, event: Any) -> None:
        self._handle_event(event, "modification")

    def on_created(self, event: Any) -> None:
        self._handle_event(event, "creation")

    def on_moved(self, event: Any) -> None:
        self._handle_event(event, "move")


class PolicyWatcher:
    """Watches the policy YAML file for disk updates using file system events."""

    def __init__(
        self,
        file_path: str,
        reload_callback: Callable[[str], None],
        debounce_interval: float = 0.05,
    ) -> None:
        self.file_path = os.path.realpath(file_path)
        self.reload_callback = reload_callback
        self.debounce_interval = float(debounce_interval)
        self.observer: Optional[Any] = None

    def start(self) -> None:
        """Starts the background directory watcher observer."""
        if self.observer is not None:
            return

        folder = os.path.dirname(self.file_path)
        handler = PolicyFileHandler(
            self.file_path, self.reload_callback, debounce_interval=self.debounce_interval
        )

        self.observer = Observer()
        self.observer.schedule(handler, path=folder, recursive=False)
        self.observer.start()
        logger.info("Policy watcher started", watch_path=self.file_path)

    def stop(self) -> None:
        """Stops and joins the watcher thread."""
        if self.observer is None:
            return
        self.observer.stop()
        self.observer.join()
        self.observer = None
        logger.info("Policy watcher stopped")

    def __enter__(self) -> "PolicyWatcher":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

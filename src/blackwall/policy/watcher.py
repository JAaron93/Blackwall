import os
import threading
import time
from typing import Any, Callable, Optional

import structlog
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = structlog.get_logger("blackwall.policy")


class PolicyFileHandler(FileSystemEventHandler):
    """File system event handler that listens for modifications to the policy YAML file with debouncing, trailing retries, and serialized reloads."""

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
        self._lock = threading.Lock()
        self._reload_lock = threading.Lock()
        self._trailing_timer: Optional[threading.Timer] = None

    def _execute_reload(self, event_type: str = "update") -> bool:
        """Executes the reload callback under lock, serializing reloads across event triggers."""
        with self._reload_lock:
            logger.info(
                f"Policy file {event_type} detected on disk. Triggering hot-reload...",
                file_path=self.file_path,
            )
            try:
                self.reload_callback(self.file_path)
                self._last_reload_time = time.time()
                return True
            except Exception as e:
                logger.error(
                    "Failed to hot-reload policy file; retaining previous valid policy.",
                    error=str(e),
                    file_path=self.file_path,
                )
                return False

    def _schedule_trailing_reload(self, event_type: str = "trailing update") -> None:
        """Schedules a trailing reload to ensure any changes during the debounce window are applied."""
        with self._lock:
            if self._trailing_timer is not None:
                self._trailing_timer.cancel()
            timer = threading.Timer(
                self.debounce_interval,
                self._on_trailing_timeout,
                args=(event_type,),
            )
            timer.daemon = True
            self._trailing_timer = timer
            timer.start()

    def _on_trailing_timeout(self, event_type: str) -> None:
        with self._lock:
            self._trailing_timer = None
        self._execute_reload(event_type)

    def cancel_pending(self) -> None:
        """Cancels any pending trailing reload timer and waits for any active reload to complete."""
        timer_to_join: Optional[threading.Timer] = None
        with self._lock:
            if self._trailing_timer is not None:
                self._trailing_timer.cancel()
                timer_to_join = self._trailing_timer
                self._trailing_timer = None

        if timer_to_join is not None and timer_to_join.is_alive():
            timer_to_join.join(timeout=2.0)

        # Wait for any in-flight reload execution to complete
        with self._reload_lock:
            pass

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
                "Scheduling trailing policy reload for event within debounce window",
                file_path=self.file_path,
            )
            self._schedule_trailing_reload(event_type)
            return

        success = self._execute_reload(event_type)
        if not success:
            # If the reload failed (e.g. incomplete YAML during atomic write),
            # schedule a trailing retry so the completed write will be re-attempted.
            self._schedule_trailing_reload(f"{event_type} retry")

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
        self.handler: Optional[PolicyFileHandler] = None

    def start(self) -> None:
        """Starts the background directory watcher observer."""
        if self.observer is not None:
            return

        folder = os.path.dirname(self.file_path)
        self.handler = PolicyFileHandler(
            self.file_path, self.reload_callback, debounce_interval=self.debounce_interval
        )

        self.observer = Observer()
        self.observer.schedule(self.handler, path=folder, recursive=False)
        self.observer.start()
        logger.info("Policy watcher started", watch_path=self.file_path)

    def stop(self) -> None:
        """Stops and joins the watcher thread."""
        if self.handler is not None:
            self.handler.cancel_pending()
            self.handler = None
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

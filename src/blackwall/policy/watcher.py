import os
from typing import Any, Callable, Optional
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
import structlog

logger = structlog.get_logger("blackwall.policy")


class PolicyFileHandler(FileSystemEventHandler):
    """File system event handler that listens for modifications to the policy YAML file."""

    def __init__(self, file_path: str, reload_callback: Callable[[str], None]) -> None:
        super().__init__()
        self.file_path = os.path.realpath(file_path)
        self.reload_callback = reload_callback

    def on_modified(self, event: Any) -> None:
        if event.is_directory:
            return

        event_path = os.path.realpath(event.src_path)
        if event_path == self.file_path:
            logger.info(
                "Policy file modification detected on disk. Triggering hot-reload...",
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


class PolicyWatcher:
    """Watches the policy YAML file for disk updates using file system events."""

    def __init__(self, file_path: str, reload_callback: Callable[[str], None]) -> None:
        self.file_path = os.path.realpath(file_path)
        self.reload_callback = reload_callback
        self.observer: Optional[Any] = None

    def start(self) -> None:
        """Starts the background directory watcher observer."""
        if self.observer is not None:
            return

        folder = os.path.dirname(self.file_path)
        handler = PolicyFileHandler(self.file_path, self.reload_callback)

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

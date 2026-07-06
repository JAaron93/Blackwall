import gzip
import logging
import logging.handlers
import os
import sys
from typing import Any

import structlog

_audit_hook_installed = False


def _gzip_rotator(source: str, dest: str) -> None:
    """Compress the rotated log file using gzip."""
    with open(source, "rb") as sf:
        with gzip.open(dest, "wb") as df:
            df.writelines(sf)
    os.remove(source)


def setup_logging(log_level: int = logging.INFO, log_dir: str = "logs") -> None:
    """Initialize structured logging with JSON formatting and rotation."""
    global _audit_hook_installed

    # Create log directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, "blackwall.log")

    # Setup TimedRotatingFileHandler
    # midnight rotation, 90 days retention, append mode
    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=log_file,
        when="midnight",
        interval=1,
        backupCount=90,
        encoding="utf-8"
    )
    # Add .gz extension to rotated files
    file_handler.rotator = _gzip_rotator
    file_handler.namer = lambda name: name + ".gz"

    stdout_handler = logging.StreamHandler(sys.stdout)

    logging.basicConfig(
        format="%(message)s",
        handlers=[file_handler, stdout_handler],
        level=log_level,
        force=True,
    )

    if not _audit_hook_installed and "pytest" not in sys.modules:

        def audit_hook(event: str, args: tuple[Any, ...]) -> None:
            if event in {"os.system", "os.posix_spawn"} or event.startswith(
                ("os.exec", "os.spawn", "subprocess.", "pty.")
            ):
                logger = structlog.get_logger("blackwall.audit")
                logger.error(
                    "CRITICAL: Raw execution bypass attempt detected via audit hook",
                    audit_event=event,
                    arguments=args,
                    severity="CRITICAL",
                )
                raise PermissionError(
                    f"Operation not permitted: raw execution bypass via {event}"
                )

        sys.addaudithook(audit_hook)
        _audit_hook_installed = True

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

import logging
import sys
from typing import Any

import structlog

_audit_hook_installed = False


def setup_logging(log_level: int = logging.INFO) -> None:
    """Initialize structured logging with JSON formatting."""
    global _audit_hook_installed

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
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

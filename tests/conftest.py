import pytest
import structlog
from structlog.testing import LogCapture


@pytest.fixture(name="log_output")
def fixture_log_output() -> LogCapture:
    return LogCapture()


@pytest.fixture(autouse=True)
def fixture_configure_structlog(log_output: LogCapture) -> None:
    structlog.configure(
        processors=[log_output],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )


@pytest.fixture
def clean_sqlite():
    def _clean(db_path: str) -> None:
        from pathlib import Path
        for path in (db_path, f"{db_path}-wal", f"{db_path}-journal", f"{db_path}-shm"):
            try:
                Path(path).unlink(missing_ok=True)
            except PermissionError:
                pass
    return _clean

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
        import os
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                pass
        for suffix in ["-wal", "-journal", "-shm"]:
            path = db_path + suffix
            if os.path.exists(path):
                try:
                    os.remove(path)
                except PermissionError:
                    pass
    return _clean

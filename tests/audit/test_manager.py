import os
import subprocess
import socket
import pytest
import time
from typing import Any, Generator, Callable
from blackwall.audit.manager import AuditHookManager
from blackwall.db.repository import SQLiteThreatRepository

TEST_DB_PATH = "test_audit.db"


@pytest.fixture
def clean_db(clean_sqlite: Callable[[str], None]) -> Generator[str, None, None]:
    clean_sqlite(TEST_DB_PATH)
    yield TEST_DB_PATH
    clean_sqlite(TEST_DB_PATH)


@pytest.fixture
def audit_manager(clean_db: str) -> Generator[AuditHookManager, None, None]:
    manager = AuditHookManager(db_path=clean_db)
    manager.start()
    yield manager
    manager.stop()


@pytest.mark.asyncio
async def test_subprocess_popen_interception(
    audit_manager: AuditHookManager, clean_db: str
) -> None:
    repo = SQLiteThreatRepository(db_path=clean_db)
    await repo.addBlockedExecutable("malicious_tool")
    await repo.close()

    with pytest.raises(PermissionError) as exc_info:
        subprocess.Popen(["malicious_tool", "--attack"])

    assert "Subprocess execution denied" in str(exc_info.value)

    repo = SQLiteThreatRepository(db_path=clean_db)
    incidents = await repo.getAuditIncidents()
    await repo.close()

    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "SUBPROCESS_EXECUTION"
    assert "malicious_tool" in incidents[0]["details"]
    assert incidents[0]["stack_trace"] is not None


def test_os_exec_interception(audit_manager: AuditHookManager, clean_db: str) -> None:
    import signal

    pid = os.fork()
    if pid == 0:
        try:
            # S606 - Intentionally checking that the hook blocks raw shell exec
            os.execv("/bin/bash", ["bash"])  # noqa: S606
        except PermissionError as e:
            if "Direct shell execution denied" in str(e):
                os._exit(42)
            os._exit(1)
        except (
            Exception
        ):  # noqa: BLE001 - Last-resort guard to ensure child never returns to pytest
            os._exit(2)
        finally:
            # Safety net: only reached if a BaseException (e.g. SystemExit/KeyboardInterrupt)
            # escapes the try-except above, since os._exit() inside except bypasses finally.
            os._exit(3)
    else:
        deadline = time.time() + 5
        status = None
        while time.time() < deadline:
            wpid, stat = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                status = stat
                break
            time.sleep(0.05)
        else:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
            pytest.fail(
                "Child did not exit in time; os.execv likely succeeded (audit hook regression)"
            )

        assert status is not None
        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 42


@pytest.mark.asyncio
async def test_socket_connect_interception(
    audit_manager: AuditHookManager, clean_db: str
) -> None:
    repo = SQLiteThreatRepository(db_path=clean_db)
    await repo.addBlockedIOC("198.51.100.24")
    await repo.close()

    s = socket.socket()
    s.settimeout(2)
    with pytest.raises(PermissionError) as exc_info:
        s.connect(("198.51.100.24", 4444))
    s.close()

    assert "Connection to malicious IOC blocked" in str(exc_info.value)

    repo = SQLiteThreatRepository(db_path=clean_db)
    incidents = await repo.getAuditIncidents()
    await repo.close()

    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "MALICIOUS_IOC_CONNECTION"
    assert "198.51.100.24:4444" in incidents[0]["details"]


@pytest.mark.asyncio
async def test_open_write_interception(
    audit_manager: AuditHookManager, clean_db: str
) -> None:
    canary_path = "/etc/blackwall_canary_test.txt"
    try:
        with pytest.raises(PermissionError) as exc_info:
            open(canary_path, "w")
        assert "File write access denied" in str(exc_info.value)
    finally:
        if os.path.exists(canary_path):
            try:
                os.remove(canary_path)
            except Exception:
                pass

    try:
        with open(canary_path, "r"):
            pass
    except PermissionError as e:
        assert "File write access denied" not in str(e)
    except FileNotFoundError:
        pass

    repo = SQLiteThreatRepository(db_path=clean_db)
    incidents = await repo.getAuditIncidents()
    await repo.close()

    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "CRITICAL_FILE_WRITE"
    assert canary_path in incidents[0]["details"]


@pytest.mark.asyncio
async def test_open_write_symlink_interception(
    audit_manager: AuditHookManager, clean_db: str
) -> None:
    canary_path = "/etc/blackwall_canary_test.txt"
    symlink_path = os.path.join(os.getcwd(), "test_symlink_to_canary")

    # Create a symlink pointing to the critical path
    if os.path.lexists(symlink_path):
        os.remove(symlink_path)
    os.symlink(canary_path, symlink_path)

    try:
        with pytest.raises(PermissionError) as exc_info:
            open(symlink_path, "w")
        assert "File write access denied" in str(exc_info.value)
    finally:
        if os.path.lexists(symlink_path):
            os.remove(symlink_path)
        if os.path.exists(canary_path):
            try:
                os.remove(canary_path)
            except Exception:
                pass

    repo = SQLiteThreatRepository(db_path=clean_db)
    incidents = await repo.getAuditIncidents()
    await repo.close()

    # The telemetry should record the blocked attempt against the resolved critical path target
    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "CRITICAL_FILE_WRITE"
    assert canary_path in incidents[0]["details"]


def test_callback_latency_metric(
    audit_manager: AuditHookManager, clean_db: str
) -> None:
    samples = []
    for _ in range(20):
        start = time.perf_counter()
        try:
            with open("benign_test_file.txt", "r"):
                pass
        except FileNotFoundError:
            pass
        samples.append((time.perf_counter() - start) * 1000.0)
    samples.sort()
    median_ms = samples[len(samples) // 2]
    assert median_ms < 5.0


@pytest.mark.asyncio
async def test_os_system_interception(
    audit_manager: AuditHookManager, clean_db: str
) -> None:
    repo = SQLiteThreatRepository(db_path=clean_db)
    await repo.addBlockedExecutable("malicious_tool")
    await repo.close()

    with pytest.raises(PermissionError) as exc_info:
        os.system("malicious_tool --attack")

    assert "System command execution denied" in str(exc_info.value)

    repo = SQLiteThreatRepository(db_path=clean_db)
    incidents = await repo.getAuditIncidents()
    await repo.close()

    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "SYSTEM_COMMAND_EXECUTION"
    assert "malicious_tool --attack" in incidents[0]["details"]


def test_unexpected_exception_fails_closed(
    audit_manager: AuditHookManager, clean_db: str
) -> None:
    # Force _evaluate_event to raise an unexpected exception
    def mock_evaluate(event: str, args: tuple[Any, ...]) -> None:
        raise ValueError("Unexpected database error")

    original_evaluate = audit_manager._evaluate_event
    audit_manager._evaluate_event = mock_evaluate  # type: ignore[assignment]

    try:
        with pytest.raises(PermissionError) as exc_info:
            audit_manager.handle_event("subprocess.Popen", ("some_tool", []))
        assert "Audit hook evaluation failed" in str(exc_info.value)
        # Ensure handling flag is cleared
        assert not audit_manager._is_handling()
    finally:
        audit_manager._evaluate_event = original_evaluate

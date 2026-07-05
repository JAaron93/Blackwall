import os
import subprocess
import socket
import pytest
import time
from typing import Generator, Callable
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
async def test_subprocess_popen_interception(audit_manager: AuditHookManager, clean_db: str) -> None:
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
            os.execv("/bin/bash", ["bash"])
        except PermissionError as e:
            if "Direct shell execution denied" in str(e):
                os._exit(42)
            os._exit(1)
        except Exception:
            os._exit(2)
        finally:
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
            pytest.fail("Child did not exit in time; os.execv likely succeeded (audit hook regression)")
        
        assert status is not None
        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 42

@pytest.mark.asyncio
async def test_socket_connect_interception(audit_manager: AuditHookManager, clean_db: str) -> None:
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
async def test_open_write_interception(audit_manager: AuditHookManager, clean_db: str) -> None:
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

def test_callback_latency_metric(audit_manager: AuditHookManager, clean_db: str) -> None:
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

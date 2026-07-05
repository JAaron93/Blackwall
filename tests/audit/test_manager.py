import os
import subprocess
import socket
import pytest
import time
from typing import Generator
from blackwall.audit.manager import AuditHookManager
from blackwall.db.repository import SQLiteThreatRepository

TEST_DB_PATH = "test_audit.db"

@pytest.fixture
def clean_db() -> Generator[str, None, None]:
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except PermissionError:
            pass
        for suffix in ["-wal", "-journal", "-shm"]:
            path = TEST_DB_PATH + suffix
            if os.path.exists(path):
                try:
                    os.remove(path)
                except PermissionError:
                    pass

    yield TEST_DB_PATH

    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except PermissionError:
            pass
        for suffix in ["-wal", "-journal", "-shm"]:
            path = TEST_DB_PATH + suffix
            if os.path.exists(path):
                try:
                    os.remove(path)
                except PermissionError:
                    pass

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
    with pytest.raises(PermissionError) as exc_info:
        os.execv("/bin/bash", ["bash"])
    
    assert "Direct shell execution denied" in str(exc_info.value)

@pytest.mark.asyncio
async def test_socket_connect_interception(audit_manager: AuditHookManager, clean_db: str) -> None:
    repo = SQLiteThreatRepository(db_path=clean_db)
    await repo.addBlockedIOC("198.51.100.24")
    await repo.close()

    s = socket.socket()
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
    with pytest.raises(PermissionError) as exc_info:
        open("/etc/passwd", "w")
    
    assert "File write access denied" in str(exc_info.value)

    try:
        with open("/etc/passwd", "r"):
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
    assert "/etc/passwd" in incidents[0]["details"]

def test_callback_latency_metric(audit_manager: AuditHookManager, clean_db: str) -> None:
    start = time.perf_counter()
    try:
        with open("benign_test_file.txt", "r"):
            pass
    except FileNotFoundError:
        pass
    duration_ms = (time.perf_counter() - start) * 1000.0
    
    assert duration_ms < 5.0

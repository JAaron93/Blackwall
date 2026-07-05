import os
import socket
import pytest
import sqlite3
import time
from typing import Generator, Dict, Any
from pytest_bdd import scenario, given, when, then
from blackwall.audit.manager import AuditHookManager

TEST_BDD_DB = "test_bdd.db"

@pytest.fixture(autouse=True)
def cleanup_bdd_db() -> Generator[None, None, None]:
    # Setup
    if os.path.exists(TEST_BDD_DB):
        try:
            os.remove(TEST_BDD_DB)
        except PermissionError:
            pass
    for suffix in ["-wal", "-journal", "-shm"]:
        path = TEST_BDD_DB + suffix
        if os.path.exists(path):
            try:
                os.remove(path)
            except PermissionError:
                pass
            
    yield
    
    # Teardown
    if os.path.exists(TEST_BDD_DB):
        try:
            os.remove(TEST_BDD_DB)
        except PermissionError:
            pass
    for suffix in ["-wal", "-journal", "-shm"]:
        path = TEST_BDD_DB + suffix
        if os.path.exists(path):
            try:
                os.remove(path)
            except PermissionError:
                pass

@scenario('../features/os_auditing.feature', 'Intercepting unauthorized socket connections at the OS level')
def test_audit_hook_socket_interception() -> None:
    pass

@given('the Python runtime audit hook "sys.addaudithook" is actively monitoring system events', target_fixture="manager")
def given_audit_hook_active() -> AuditHookManager:
    manager = AuditHookManager(db_path=TEST_BDD_DB)
    manager.start()
    return manager

@given('the local SQLite IOC blacklist contains IP address "198.51.100.24"')
def given_ioc_blacklist_contains() -> None:
    db_dir = os.path.dirname(os.path.abspath(TEST_BDD_DB))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(TEST_BDD_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_iocs (
            ioc TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
    """)
    conn.execute(
        "INSERT OR IGNORE INTO blocked_iocs (ioc, type, created_at) VALUES (?, ?, ?)",
        ("198.51.100.24", "ip", int(time.time()))
    )
    conn.commit()
    conn.close()

@when('an execution agent runs a Python script attempting "socket.connect" to "198.51.100.24:4444"', target_fixture="conn_result")
def when_attempt_socket_connect(manager: AuditHookManager) -> Dict[str, Any]:
    s = socket.socket()
    exc = None
    try:
        s.connect(("198.51.100.24", 4444))
    except Exception as e:
        exc = e
    finally:
        s.close()
        manager.stop()
    return {"exception": exc}

@then('the audit hook must trap the "socket.connect" event before OS kernel execution')
def then_audit_hook_trapped(conn_result: Dict[str, Any]) -> None:
    assert conn_result["exception"] is not None

@then('the system must raise an immediate "PermissionError" exception')
def then_raise_permission_error(conn_result: Dict[str, Any]) -> None:
    assert isinstance(conn_result["exception"], PermissionError)
    assert "Connection to malicious IOC blocked" in str(conn_result["exception"])

@then('an incident telemetry record must be written atomically to the SQLite WAL database')
def then_telemetry_written() -> None:
    conn = sqlite3.connect(TEST_BDD_DB)
    cursor = conn.execute("SELECT incident_type, details FROM audit_incidents ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][0] == "MALICIOUS_IOC_CONNECTION"
    assert "198.51.100.24:4444" in rows[0][1]

@then('the outbound network connection must be severed completely')
def then_connection_severed(conn_result: Dict[str, Any]) -> None:
    assert conn_result["exception"] is not None

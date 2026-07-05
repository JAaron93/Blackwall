import asyncio
import socket
import pytest
from typing import Generator, Dict, Any, Callable
from pytest_bdd import scenario, given, when, then
from blackwall.audit.manager import AuditHookManager
from blackwall.db.repository import SQLiteThreatRepository

TEST_BDD_DB = "test_bdd.db"

@pytest.fixture(autouse=True)
def cleanup_bdd_db(clean_sqlite: Callable[[str], None]) -> Generator[None, None, None]:
    clean_sqlite(TEST_BDD_DB)
    yield
    clean_sqlite(TEST_BDD_DB)

@scenario('../features/os_auditing.feature', 'Intercepting unauthorized socket connections at the OS level')
def test_audit_hook_socket_interception() -> None:
    pass

@given('the Python runtime audit hook "sys.addaudithook" is actively monitoring system events', target_fixture="manager")
def given_audit_hook_active(request: pytest.FixtureRequest) -> AuditHookManager:
    manager = AuditHookManager(db_path=TEST_BDD_DB)
    manager.start()
    request.addfinalizer(manager.stop)
    return manager

@given('the local SQLite IOC blacklist contains IP address "198.51.100.24"')
def given_ioc_blacklist_contains() -> None:
    async def _seed() -> None:
        repo = SQLiteThreatRepository(db_path=TEST_BDD_DB)
        await repo.initialize()
        await repo.addBlockedIOC("198.51.100.24")
        await repo.close()
        
    asyncio.run(_seed())

@when('an execution agent runs a Python script attempting "socket.connect" to "198.51.100.24:4444"', target_fixture="conn_result")
def when_attempt_socket_connect(manager: AuditHookManager) -> Dict[str, Any]:
    s = socket.socket()
    s.settimeout(2)
    exc = None
    try:
        s.connect(("198.51.100.24", 4444))
    except Exception as e:
        exc = e
    finally:
        s.close()
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
    async def _fetch() -> list[Dict[str, Any]]:
        repo = SQLiteThreatRepository(db_path=TEST_BDD_DB)
        incidents = await repo.getAuditIncidents()
        await repo.close()
        return incidents
        
    incidents = asyncio.run(_fetch())
    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "MALICIOUS_IOC_CONNECTION"
    assert "198.51.100.24:4444" in incidents[0]["details"]

@then('the outbound network connection must be severed completely')
def then_connection_severed(conn_result: Dict[str, Any]) -> None:
    assert conn_result["exception"] is not None

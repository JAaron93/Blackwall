# ADR 0001: Synchronous Database Access and Blocklist Management for OS-Level Audit Hooks

## Status
Approved

## Context
Python's native `sys.addaudithook` triggers callback events synchronously before the OS kernel processes the low-level calls (e.g. `subprocess.Popen`, `socket.connect`, `open`). 

The `SQLiteThreatRepository` in Blackwall uses `aiosqlite` for asynchronous connection pooling. However, synchronous audit hook callbacks cannot run or await asynchronous coroutines safely, especially since the event loop might be blocked or absent on the invoking thread.

Furthermore, the audit hook callback has a strict execution overhead budget of `<1ms`. Querying a generalized `signatures` table containing complex structural threat relationships would introduce query parsing overhead and potential locking conflicts, violating this constraint.

Finally, low-level database operations (like opening a connection or logging to `audit_incidents`) themselves trigger audit events (e.g., `open`). Without protection, this would cause infinite re-entrancy loops and crash the Python process.

## Decision
We implemented the following architectural solutions:

1. **Synchronous Thread-Local Connections:**
   `AuditHookManager` bypasses the asynchronous repository pool and maintains a synchronous `sqlite3.Connection` per thread using `threading.local()`. This ensures thread-safety and avoids connection lock contentions during concurrent execution threads.

2. **Dedicated Blocklist Tables:**
   We created dedicated SQLite tables (`blocked_executables` and `blocked_iocs`) with simple indexes. Queries use exact match lookups (`SELECT 1 FROM ... WHERE ... = ?`), allowing check operations to complete in `<0.1ms` (well below the 1ms budget).

3. **Re-Entrancy Mitigation:**
   We introduced a thread-local flag (`self._local.handling`) in `AuditHookManager`. Before evaluating any event, the manager sets this flag to `True`. If the flag is already `True`, the hook immediately returns. This prevents the hook from recursively intercepting its own database lookups, database file opens, or telemetry writes.

4. **Synchronous Telemetry Logging:**
   Incidents are written directly and synchronously to the `audit_incidents` table in SQLite WAL mode, ensuring atomic and fast persistence before raising `PermissionError`.

## Consequences
- **Pros:**
  - Zero async/sync bridge complexity.
  - High performance: Callback execution overhead is virtually imperceptible (<0.1ms for benign actions).
  - High resilience: Thread-local connections prevent multi-threading race conditions.
  - Infinite loops and stack overflows are completely prevented via the re-entrancy guard.
- **Cons:**
  - The blocklist must be populated in these dedicated tables (`blocked_executables` and `blocked_iocs`), meaning the system must synchronize threat intelligence updates from the main `signatures` graph into these tables.

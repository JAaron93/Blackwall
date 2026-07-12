import os
import sys
import tempfile
import asyncio
import atexit
import uvicorn
from fastapi import FastAPI, HTTPException, Query

# Ensure we can import blackwall from src/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from blackwall import AuditHookManager
from blackwall.db.pool import AsyncConnectionPool

# Initialize and start the Audit Hook Manager process-wide
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "blackwall.db"))
audit_manager = AuditHookManager(db_path=db_path)
audit_manager.start()

app = FastAPI(title="Vulnerable Mock Application (FastAPI)")

# Setup a WAL-enabled connection pool backed by a securely created temporary demo database
demo_db_fd, demo_db_path = tempfile.mkstemp(suffix=".db", prefix="blackwall_demo_")
os.close(demo_db_fd)  # Close the file descriptor, pool will open it
db_pool = AsyncConnectionPool(db_path=demo_db_path, max_connections=10)

def cleanup_demo_db():
    """Clean up the temporary database file on process exit."""
    if os.path.exists(demo_db_path):
        try:
            os.remove(demo_db_path)
        except Exception:
            pass

atexit.register(cleanup_demo_db)

@app.on_event("startup")
async def startup_event():
    """Initialize the database schema and seed records through the pool."""
    await db_pool.initialize()
    async with db_pool.connection() as conn:
        await conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, secret_token TEXT)")
        # Check if data is already seeded
        cursor = await conn.execute("SELECT COUNT(*) FROM users")
        row = await cursor.fetchone()
        if row and row[0] == 0:
            await conn.executemany("INSERT INTO users (username, role, secret_token) VALUES (?, ?, ?)", [
                ("admin", "administrator", "super-secret-token-123"),
                ("alice", "user", "alice-token-456"),
                ("bob", "user", "bob-token-789")
            ])

@app.on_event("shutdown")
async def shutdown_event():
    """Close the connection pool and clean up the temporary database on shutdown."""
    await db_pool.close()
    cleanup_demo_db()

@app.get("/api/users")
async def get_users(username: str = Query(...)):
    # Vulnerable SQL Injection surface
    query = f"SELECT username, role FROM users WHERE username = '{username}'"  # noqa: S608
    try:
        async with db_pool.connection() as conn:
            cursor = await conn.execute(query)
            results = await cursor.fetchall()
        return [{"username": r[0], "role": r[1]} for r in results]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

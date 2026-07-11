import os
import sys
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, Query

# Ensure we can import blackwall from src/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from blackwall import AuditHookManager

# Initialize and start the Audit Hook Manager process-wide
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "blackwall.db"))
audit_manager = AuditHookManager(db_path=db_path)
audit_manager.start()

app = FastAPI(title="Vulnerable Mock Application (FastAPI)")

# Setup a vulnerable in-memory database with some dummy records
import threading
db_lock = threading.Lock()

conn = sqlite3.connect(":memory:", check_same_thread=False)
with db_lock:
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, secret_token TEXT)")
    conn.executemany("INSERT INTO users (username, role, secret_token) VALUES (?, ?, ?)", [
        ("admin", "administrator", "super-secret-token-123"),
        ("alice", "user", "alice-token-456"),
        ("bob", "user", "bob-token-789")
    ])
    conn.commit()

@app.get("/api/users")
def get_users(username: str = Query(...)):
    # Vulnerable SQL Injection surface
    query = f"SELECT username, role FROM users WHERE username = '{username}'"  # noqa: S608
    try:
        with db_lock:
            cursor = conn.execute(query)
            results = cursor.fetchall()
        return [{"username": r[0], "role": r[1]} for r in results]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

@app.post("/api/shutdown")
def shutdown():
    audit_manager.stop()
    # Simple hard exit to shut down the server
    os._exit(0)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

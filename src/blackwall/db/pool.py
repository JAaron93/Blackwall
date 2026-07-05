import asyncio
import aiosqlite
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class AsyncConnectionPool:
    def __init__(self, db_path: str, max_connections: int = 10):
        self.db_path = db_path
        self.max_connections = max_connections
        self._pool: Optional[asyncio.Queue[aiosqlite.Connection]] = None
        self._initialized = False
        self._init_lock = asyncio.Lock()

    async def _init_connection(self) -> aiosqlite.Connection:
        conn = await aiosqlite.connect(self.db_path)
        # Configure connection for WAL mode and performance
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        await conn.execute("PRAGMA wal_autocheckpoint=1000;")
        await conn.commit()
        return conn

    async def initialize(self):
        if self._initialized:
            return
            
        async with self._init_lock:
            if self._initialized:
                return
                
            self._pool = asyncio.Queue(maxsize=self.max_connections)
            for _ in range(self.max_connections):
                conn = await self._init_connection()
                self._pool.put_nowait(conn)
                
            self._initialized = True

    async def close(self):
        if not self._initialized or self._pool is None:
            return
            
        async with self._init_lock:
            while not self._pool.empty():
                conn = self._pool.get_nowait()
                await conn.close()
                
            self._initialized = False

    async def acquire(self) -> aiosqlite.Connection:
        if not self._initialized or self._pool is None:
            await self.initialize()
            
        if self._pool is None:
            raise RuntimeError("Pool initialization failed")
            
        # This will block if all connections are currently in use
        conn = await self._pool.get()
        return conn

    def release(self, conn: aiosqlite.Connection):
        if self._pool is None:
            return
        self._pool.put_nowait(conn)

    class TransactionContext:
        def __init__(self, pool: 'AsyncConnectionPool'):
            self.pool = pool
            self.conn = None

        async def __aenter__(self) -> aiosqlite.Connection:
            self.conn = await self.pool.acquire()
            return self.conn

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            if self.conn:
                if exc_type is None:
                    await self.conn.commit()
                else:
                    await self.conn.rollback()
                self.pool.release(self.conn)

    def connection(self):
        """Context manager to acquire and release a connection automatically."""
        return self.TransactionContext(self)

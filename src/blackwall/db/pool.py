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
        try:
            # Configure connection for WAL mode and performance
            await conn.execute("PRAGMA journal_mode=WAL;")
            await conn.execute("PRAGMA busy_timeout=5000;")
            await conn.execute("PRAGMA synchronous=NORMAL;")
            await conn.execute("PRAGMA wal_autocheckpoint=1000;")
            await conn.execute("PRAGMA foreign_keys=ON;")
            await conn.commit()
        except Exception:
            # PRAGMA setup can fail (e.g. corrupt/non-database file) after the
            # aiosqlite worker thread has started. Close the connection so the
            # non-daemon worker thread terminates instead of leaking and
            # blocking interpreter exit in threading._shutdown.
            try:
                await conn.close()
            except Exception:
                pass
            raise
        return conn

    async def initialize(self) -> None:
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if hasattr(self, "_loop") and self._loop is not None and self._loop is not current_loop:
            if self._pool is not None:
                while not self._pool.empty():
                    conn = self._pool.get_nowait()
                    try:
                        await conn.close()
                    except Exception:
                        pass
            self._initialized = False
            self._pool = None
            self._init_lock = asyncio.Lock()
        self._loop = current_loop

        if self._initialized:
            return

        async with self._init_lock:
            if self._initialized:
                return

            self._pool = asyncio.Queue(maxsize=self.max_connections)
            try:
                for _ in range(self.max_connections):
                    conn = await self._init_connection()
                    self._pool.put_nowait(conn)
            except Exception:
                # A mid-loop failure (e.g. corrupt file) must not abandon the
                # connections created so far: each holds a non-daemon aiosqlite
                # worker thread that would otherwise leak and block process exit.
                while not self._pool.empty():
                    conn = self._pool.get_nowait()
                    try:
                        await conn.close()
                    except Exception:
                        pass
                self._pool = None
                raise

            self._initialized = True

    async def close(self) -> None:
        if self._pool is None:
            return

        async with self._init_lock:
            while self._pool is not None and not self._pool.empty():
                conn = self._pool.get_nowait()
                try:
                    await conn.close()
                except Exception as e:
                    logger.debug("Error closing connection: %s", e)

            self._initialized = False
            self._pool = None

    async def acquire(self) -> aiosqlite.Connection:
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if (
            not self._initialized
            or self._pool is None
            or (hasattr(self, "_loop") and self._loop is not current_loop)
        ):
            await self.initialize()

        if self._pool is None:
            raise RuntimeError("Pool initialization failed")

        # This will block if all connections are currently in use
        conn = await self._pool.get()
        return conn

    def release(self, conn: aiosqlite.Connection) -> None:
        if self._pool is None:
            return
        self._pool.put_nowait(conn)

    class TransactionContext:
        def __init__(self, pool: "AsyncConnectionPool") -> None:
            self.pool = pool
            self.conn: Optional[aiosqlite.Connection] = None

        async def __aenter__(self) -> aiosqlite.Connection:
            self.conn = await self.pool.acquire()
            return self.conn

        async def __aexit__(
            self,
            exc_type: Optional[type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[object],
        ) -> None:
            if self.conn:
                try:
                    if exc_type is None:
                        await self.conn.commit()
                    else:
                        await self.conn.rollback()
                finally:
                    self.pool.release(self.conn)

    def connection(self) -> "AsyncConnectionPool.TransactionContext":
        """Context manager to acquire and release a connection automatically."""
        return self.TransactionContext(self)

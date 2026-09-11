"""
ZeroMQ Pub/Sub Threat Mesh Receiver & Ingestion Worker (`blackwall.enterprise.mesh.receiver`).
Subscribes to distributed threat signature broadcasts and ingests them into SQLite.
Satisfies TASK-M02, FR-05, FR-06, NFR-01, NFR-02.
"""

import asyncio
import json
import logging
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from types import TracebackType
from typing import Any, Self

try:
    import zmq
    import zmq.asyncio
    HAS_ZMQ = True
except ImportError:
    zmq = None
    HAS_ZMQ = False

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.enterprise.mesh.broadcaster import DEFAULT_MESH_ENDPOINT

logger = logging.getLogger("blackwall.enterprise.mesh.receiver")


class MeshReceiver:
    """Subscribes to ZeroMQ threat mesh broadcasts and ingests signatures into SQLite."""

    def __init__(
        self,
        endpoint: str = DEFAULT_MESH_ENDPOINT,
        repository: SQLiteThreatRepository | None = None,
        db_path: str = "./blackwall.db",
        topic: str = "",
        connect: bool = True,
        warmup_delay_s: float = 0.05,
    ) -> None:
        self.endpoint = endpoint
        self.topic = topic
        self.connect = connect
        self.db_path = db_path
        self.repository = repository or SQLiteThreatRepository(db_path=db_path)
        self.warmup_delay_s = warmup_delay_s

        self._context: Any | None = None
        self._socket: Any | None = None
        self._worker_task: asyncio.Task[None] | None = None
        self._is_active: bool = False
        self._is_ready: bool = False
        self._lock = asyncio.Lock()

        # Telemetry & Callbacks
        self.signatures_ingested_count: int = 0
        self.last_latency_ms: float = 0.0
        self.on_signature_received: Callable[[dict[str, Any]], Any] | None = None
        self._inbound_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)

    @property
    def is_active(self) -> bool:
        """Returns True if the receiver socket and ingestion worker are active."""
        return self._is_active

    @property
    def is_ready(self) -> bool:
        """Returns True if the receiver socket has connected and completed warmup."""
        return self._is_active and self._is_ready

    async def wait_until_ready(self, timeout: float = 0.08) -> None:
        """Awaits ZeroMQ subscription handshake settlement across nodes."""
        if self._is_ready:
            return
        if not self._is_active:
            await self.start()
            if self._is_ready:
                return

        delay = self.warmup_delay_s if self.warmup_delay_s > 0 else timeout
        wait_time = min(delay, timeout) if timeout > 0 else delay
        if wait_time > 0:
            await asyncio.sleep(wait_time)
        self._is_ready = True

    async def start(self) -> None:
        """Initializes SUB socket, connects/binds, and launches background ingestion loop."""
        if self._is_active and self._is_ready:
            return

        if not HAS_ZMQ:
            raise ImportError(
                "pyzmq is required for Blackwall Enterprise Threat Mesh. "
                "Install it with: pip install pyzmq"
            )

        async with self._lock:
            if self._is_active and self._is_ready:
                return

            try:
                if not self._is_active:
                    await self.repository.initialize()

                    self._context = zmq.asyncio.Context()
                    self._socket = self._context.socket(zmq.SUB)
                    self._socket.setsockopt(zmq.LINGER, 0)
                    # Subscribe to topic prefix (empty string subscribes to all messages)
                    self._socket.setsockopt(zmq.SUBSCRIBE, self.topic.encode("utf-8"))

                    if self.connect:
                        self._socket.connect(self.endpoint)
                    else:
                        self._socket.bind(self.endpoint)

                    self._is_active = True
                    self._worker_task = asyncio.create_task(self._ingestion_loop())
                    logger.debug(
                        "MeshReceiver active on %s (topic=%r, connect=%s)",
                        self.endpoint,
                        self.topic,
                        self.connect,
                    )

                if self.warmup_delay_s > 0:
                    if not self._is_ready:
                        await asyncio.sleep(self.warmup_delay_s)
                    self._is_ready = True
            except Exception as exc:
                logger.error("Failed to start MeshReceiver on %s: %s", self.endpoint, exc)
                await self.stop()
                raise

    async def stop(self) -> None:
        """Stops background worker, drains in-flight items, and terminates sockets cleanly."""
        if not self._is_active and self._socket is None:
            return

        self._is_active = False
        self._is_ready = False

        if self._worker_task is not None:
            try:
                loop = self._worker_task.get_loop()
                if not loop.is_closed():
                    self._worker_task.cancel()
                    await self._worker_task
            except (asyncio.CancelledError, RuntimeError):
                pass
            finally:
                self._worker_task = None

        if self._socket is not None:
            try:
                self._socket.close(linger=0)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Error closing receiver socket: %s", exc)
            finally:
                self._socket = None

        if self._context is not None:
            try:
                self._context.term()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Error terminating receiver context: %s", exc)
            finally:
                self._context = None

    def _parse_message(self, frames: list[bytes]) -> dict[str, Any] | None:
        """Parses multipart or single-frame ZeroMQ message into dictionary."""
        try:
            if len(frames) >= 2:
                # Frame 0 is topic, Frame 1 is JSON payload
                payload_bytes = frames[1]
            elif len(frames) == 1:
                raw = frames[0]
                # Try single-frame with space delimiter
                if b" " in raw:
                    _, payload_bytes = raw.split(b" ", 1)
                else:
                    payload_bytes = raw
            else:
                return None

            return json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse mesh message: %s", exc)
            return None

    def _normalize_signature(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """Normalizes incoming payload into SQLiteThreatRepository signature schema.

        Rejects signatures with missing or empty payload patterns to prevent wildcard
        matching vulnerabilities.
        """
        pattern = str(data.get("payload_pattern") or data.get("pattern") or "").strip()
        if not pattern:
            logger.warning(
                "Rejecting invalid threat signature: empty or missing payload pattern in message: %s",
                data,
            )
            return None

        raw_id = data.get("signature_id") or data.get("signatureId")
        sig_id = str(raw_id) if raw_id else f"mesh_sig_{uuid.uuid4().hex[:12]}"

        intent = str(data.get("attacker_intent") or data.get("intent") or data.get("threat_level") or "UNKNOWN")
        tool = str(data.get("target_tool") or data.get("tool") or "ANY")
        sink = str(data.get("target_sink") or data.get("sink") or "PROCESS")
        mitigation = str(data.get("mitigation_action") or data.get("action") or "BLOCK")

        created_at = data.get("created_at") or data.get("createdAt")
        if isinstance(created_at, (int, float)):
            created_ts = int(created_at)
        elif isinstance(created_at, str):
            try:
                created_ts = int(datetime.fromisoformat(created_at).timestamp())
            except (ValueError, TypeError):
                created_ts = int(time.time())
        else:
            created_ts = int(time.time())

        return {
            "signatureId": sig_id,
            "signature_id": sig_id,
            "createdAt": created_ts,
            "attackerIntent": intent,
            "payloadPattern": pattern,
            "targetTool": tool,
            "targetSink": sink,
            "mitigationAction": mitigation,
            "metadata": data.get("metadata", {}),
        }

    async def _ingest_signature(self, raw_data: dict[str, Any]) -> str | None:
        """Normalizes and writes signature to SQLite repository."""
        normalized = self._normalize_signature(raw_data)
        if normalized is None:
            return None

        sig_id = await self.repository.writeSignature(normalized)
        self.signatures_ingested_count += 1

        if self.on_signature_received is not None:
            try:
                res = self.on_signature_received(normalized)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as exc:  # noqa: BLE001
                logger.warning("Error in on_signature_received callback: %s", exc)

        return sig_id

    async def _ingestion_loop(self) -> None:
        """Continuous background worker receiving messages and writing to SQLite."""
        while self._is_active and self._socket is not None:
            try:
                frames = await self._socket.recv_multipart()

                data = self._parse_message(frames)
                if data is not None:
                    sig_id = await self._ingest_signature(data)
                    if sig_id is not None:
                        try:
                            self._inbound_queue.put_nowait(data)
                        except asyncio.QueueFull:
                            try:
                                self._inbound_queue.get_nowait()
                                self._inbound_queue.put_nowait(data)
                            except (asyncio.QueueEmpty, asyncio.QueueFull):
                                pass

                    # Update latency metric if created_at exists
                    created_at = data.get("created_at") or data.get("timestamp")
                    if isinstance(created_at, (int, float)):
                        self.last_latency_ms = (time.time() - float(created_at)) * 1000.0
            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001
                if self._is_active:
                    logger.error("Error in MeshReceiver ingestion loop: %s", exc)
                    await asyncio.sleep(0.01)

    async def receive_one(self, timeout: float = 1.0) -> dict[str, Any] | None:
        """Awaits and returns a single ingested signature from the background ingestion queue."""
        if not self._is_active:
            await self.start()

        try:
            return await asyncio.wait_for(self._inbound_queue.get(), timeout=timeout)
        except TimeoutError:
            return None

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.stop()

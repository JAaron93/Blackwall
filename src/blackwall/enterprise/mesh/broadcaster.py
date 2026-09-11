"""
ZeroMQ Pub/Sub Threat Mesh Broadcaster (`blackwall.enterprise.mesh.broadcaster`).
Publishes threat signatures and security reactions across cluster nodes.
Satisfies TASK-M01, FR-04, NFR-02.
"""

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Self

try:
    import zmq
    import zmq.asyncio
    HAS_ZMQ = True
except ImportError:
    zmq = None
    HAS_ZMQ = False

logger = logging.getLogger("blackwall.enterprise.mesh.broadcaster")

DEFAULT_MESH_ENDPOINT = "tcp://127.0.0.1:5555"
DEFAULT_MESH_TOPIC = "threat_signatures"


class MeshBroadcaster:
    """Publishes dynamic threat signatures over ZeroMQ PUB sockets."""

    def __init__(
        self,
        endpoint: str = DEFAULT_MESH_ENDPOINT,
        topic: str = DEFAULT_MESH_TOPIC,
        bind: bool = True,
        warmup_delay_s: float = 0.05,
    ) -> None:
        self.endpoint = endpoint
        self.topic = topic
        self.bind = bind
        self.warmup_delay_s = warmup_delay_s
        self._context: Any | None = None
        self._socket: Any | None = None
        self._sync_context: Any | None = None
        self._sync_socket: Any | None = None
        self._is_active: bool = False
        self._is_ready: bool = False
        self._lock = asyncio.Lock()

    @property
    def is_active(self) -> bool:
        """Returns True if the async broadcaster socket is initialized and active."""
        return self._is_active

    @property
    def is_ready(self) -> bool:
        """Returns True if the broadcaster has completed its warmup handshake period."""
        return self._is_active and self._is_ready

    async def start(self) -> None:
        """Initializes the ZeroMQ PUB socket, binds/connects, and allows warmup handshake."""
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
                    self._context = zmq.asyncio.Context()
                    self._socket = self._context.socket(zmq.PUB)
                    self._socket.setsockopt(zmq.LINGER, 0)

                    if self.bind:
                        self._socket.bind(self.endpoint)
                    else:
                        self._socket.connect(self.endpoint)

                    self._is_active = True
                    logger.debug("MeshBroadcaster active on endpoint %s (bind=%s)", self.endpoint, self.bind)

                # Slow joiner mitigation: allow ZeroMQ PUB/SUB handshake to settle
                if self.warmup_delay_s > 0 and not self._is_ready:
                    await asyncio.sleep(self.warmup_delay_s)

                self._is_ready = True
            except Exception as exc:
                logger.error("Failed to start MeshBroadcaster on %s: %s", self.endpoint, exc)
                await self.stop()
                raise

    async def stop(self) -> None:
        """Closes sockets and terminates ZeroMQ context cleanly."""
        if not self._is_active and self._socket is None and self._sync_socket is None:
            return

        self._is_active = False
        self._is_ready = False

        if self._socket is not None:
            try:
                self._socket.close(linger=0)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Error closing async zmq socket: %s", exc)
            finally:
                self._socket = None

        if self._context is not None:
            try:
                self._context.term()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Error terminating async zmq context: %s", exc)
            finally:
                self._context = None

        if self._sync_socket is not None:
            try:
                self._sync_socket.close(linger=0)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Error closing sync zmq socket: %s", exc)
            finally:
                self._sync_socket = None

        if self._sync_context is not None:
            try:
                self._sync_context.term()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Error terminating sync zmq context: %s", exc)
            finally:
                self._sync_context = None

    def _serialize_payload(self, payload: Any) -> bytes:
        """Serializes dictionary or Pydantic model into JSON bytes."""
        if hasattr(payload, "model_dump") and callable(payload.model_dump):
            data = payload.model_dump(mode="json")
        elif isinstance(payload, dict):
            data = payload
        elif hasattr(payload, "__dict__"):
            data = vars(payload)
        else:
            data = {"raw_payload": str(payload)}

        def _json_default(obj: Any) -> Any:
            if isinstance(obj, uuid.UUID):
                return str(obj)
            if isinstance(obj, datetime):
                return obj.isoformat()
            if hasattr(obj, "value"):
                return obj.value
            return str(obj)

        return json.dumps(data, default=_json_default).encode("utf-8")

    async def broadcast(self, payload: Any, topic: str | None = None) -> bool:
        """Asynchronously publishes threat signature payload over ZeroMQ pub/sub sockets."""
        if not self._is_active or not self._is_ready:
            await self.start()

        if self._socket is None:
            return False

        try:
            target_topic = (topic or self.topic).encode("utf-8")
            payload_bytes = self._serialize_payload(payload)

            # Send multipart frame: [topic, json_payload]
            await self._socket.send_multipart([target_topic, payload_bytes])
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to broadcast threat signature: %s", exc)
            return False

    def broadcast_sync(self, payload: Any, topic: str | None = None) -> bool:
        """Synchronously publishes payload without requiring an active asyncio event loop."""
        if not HAS_ZMQ:
            raise ImportError(
                "pyzmq is required for Blackwall Enterprise Threat Mesh. "
                "Install it with: pip install pyzmq"
            )

        try:
            if self._sync_socket is None:
                self._sync_context = zmq.Context()
                self._sync_socket = self._sync_context.socket(zmq.PUB)
                self._sync_socket.setsockopt(zmq.LINGER, 0)
                if self.bind:
                    self._sync_socket.bind(self.endpoint)
                else:
                    self._sync_socket.connect(self.endpoint)

                if self.warmup_delay_s > 0:
                    import time
                    time.sleep(self.warmup_delay_s)

            target_topic = (topic or self.topic).encode("utf-8")
            payload_bytes = self._serialize_payload(payload)

            self._sync_socket.send_multipart([target_topic, payload_bytes])
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to broadcast threat signature synchronously: %s", exc)
            return False

    async def broadcast_threat_signature(
        self,
        signature: str,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Duck-typed method invoked by ActiveReactionEngine to broadcast threat signatures."""
        payload = {
            "signature_id": f"mesh_sig_{uuid.uuid4().hex[:12]}",
            "pattern": signature,
            "threat_level": "CRITICAL",
            "attacker_intent": "AGENTIC_EXPLOIT_BLOCK",
            "target_tool": "ANY",
            "created_at": datetime.now(UTC).isoformat(),
            "metadata": metadata or {},
        }
        return await self.broadcast(payload)

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

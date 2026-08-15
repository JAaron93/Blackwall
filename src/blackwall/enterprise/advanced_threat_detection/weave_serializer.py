"""Weave Trace Serializer with security and privacy sanitization invariants.

Subtask 22.3: Weave Traced Wrappers and WeaveTraceSerializer.
Requirements 17 & 18.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from blackwall.enterprise.advanced_threat_detection.models import (
    AttackPath,
)


class WeaveTraceSerializer:
    """Serializer ensuring data sanitization and size enforcement for Weave traces."""

    SENSITIVE_KEY_PATTERNS: tuple[str, ...] = (
        "credential",
        "secret",
        "token",
        "password",
        "key",
        "api_key",
        "auth",
        "private",
        "cert",
    )

    @staticmethod
    def _format_timestamp(dt: datetime) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.isoformat()

    @classmethod
    def serialize_event(cls, event: Any) -> dict[str, Any]:
        """Sanitize a NormalizedEvent (or event object/dict) to export ONLY safe metadata.

        Drops action, target, metadata, and prompt payloads.
        """
        if isinstance(event, dict):
            event_id = str(event.get("event_id", ""))
            agent_id = str(event.get("agent_id", ""))
            ts = event.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except Exception:  # noqa: BLE001
                    ts = datetime.now(UTC)
            elif isinstance(ts, datetime):
                pass
            else:
                ts = datetime.now(UTC)
            source_raw = event.get("source", "")
            source_val = (
                source_raw.value if hasattr(source_raw, "value") else str(source_raw)
            )
            risk_score = float(event.get("risk_score", 0.0))
            payload: dict[str, Any] = {
                "event_id": event_id,
                "agent_id": agent_id,
                "timestamp": cls._format_timestamp(ts),
                "source": source_val,
                "risk_score": risk_score,
            }
            return cls.enforce_size(payload)

        source_val = (
            event.source.value if hasattr(event.source, "value") else str(event.source)
        )
        payload = {
            "event_id": str(event.event_id),
            "agent_id": str(event.agent_id),
            "timestamp": cls._format_timestamp(event.timestamp),
            "source": source_val,
            "risk_score": float(event.risk_score),
        }
        return cls.enforce_size(payload)

    @classmethod
    def serialize_path(cls, path: AttackPath) -> dict[str, Any]:
        """Sanitize an AttackPath, replacing node payloads with node count."""
        stages = [
            s.value if hasattr(s, "value") else str(s) for s in path.attack_stages
        ]
        payload: dict[str, Any] = {
            "path_id": str(path.path_id),
            "agent_id": str(path.agent_id),
            "start_time": cls._format_timestamp(path.start_time),
            "end_time": cls._format_timestamp(path.end_time),
            "risk_score": float(path.risk_score),
            "attack_stages": stages,
            "correlation_score": float(path.correlation_score),
            "node_count": len(path.nodes),
        }
        return cls.enforce_size(payload)

    @classmethod
    def serialize_swarm(cls, swarm: Any) -> dict[str, Any]:
        """Sanitize a SwarmEvidence (or swarm object) payload."""
        payload: dict[str, Any] = {
            "swarm_id": str(swarm.swarm_id),
            "agent_ids": sorted(swarm.agent_ids),
            "temporal_correlation": float(swarm.temporal_correlation),
            "coordination_score": float(swarm.coordination_score),
            "first_seen": cls._format_timestamp(swarm.first_seen),
            "last_seen": cls._format_timestamp(swarm.last_seen),
        }
        return cls.enforce_size(payload)

    @classmethod
    def mask_metadata(cls, metadata: Any) -> Any:
        """Recursively mask sensitive keys in metadata dicts/lists/tuples."""
        if isinstance(metadata, dict):
            masked_dict: dict[str, Any] = {}
            for k, v in metadata.items():
                k_lower = str(k).lower()
                if any(pat in k_lower for pat in cls.SENSITIVE_KEY_PATTERNS):
                    masked_dict[k] = "**REDACTED**"
                elif isinstance(v, (dict, list, tuple)):
                    masked_dict[k] = cls.mask_metadata(v)
                elif hasattr(v, "__class__") and not isinstance(
                    v, (int, float, str, bool, type(None))
                ):
                    if hasattr(v, "event_id") and hasattr(v, "risk_score"):
                        masked_dict[k] = cls.serialize_event(v)
                    elif hasattr(v, "path_id") and hasattr(v, "attack_stages"):
                        masked_dict[k] = cls.serialize_path(v)
                    elif hasattr(v, "swarm_id") and hasattr(v, "coordination_score"):
                        masked_dict[k] = cls.serialize_swarm(v)
                    else:
                        masked_dict[k] = str(v)
                else:
                    masked_dict[k] = v
            return masked_dict

        if isinstance(metadata, list):
            return [cls.mask_metadata(item) for item in metadata]

        if isinstance(metadata, tuple):
            return tuple(cls.mask_metadata(item) for item in metadata)

        return metadata

    @staticmethod
    def enforce_size(payload: dict[str, Any], max_bytes: int = 4096) -> dict[str, Any]:
        """Enforce maximum byte size limit for serialized trace payloads."""
        try:
            raw_bytes = json.dumps(payload, default=str).encode("utf-8")
            if len(raw_bytes) > max_bytes:
                return {
                    "_truncated": True,
                    "_original_bytes": len(raw_bytes),
                }
        except Exception:  # noqa: BLE001, S110
            pass
        return payload

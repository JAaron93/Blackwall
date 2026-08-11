"""
src/blackwall/attribution/extractor.py — Attacker Identity Extractor.

Extracts multi-layered attacker identity attributes from ADK tool call context
metadata and local process information.

Design Constraints (per design.md §4):
  - Non-blocking: pure Python, no I/O, no network calls (NFR-1, <5ms)
  - Fail-closed: exceptions return UNRESOLVED_ATTACKER identity, never propagate (NFR-2)
  - Privacy-safe: called AFTER ContextResolver sanitization (FR-6)
  - Zero C-dependencies: uses only hashlib, os, psutil, pydantic (NFR-3)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from blackwall.models import AttackerIdentity, IdentitySource, ToolCallContext

logger = logging.getLogger(__name__)

# Sentinel values used for the degraded "UNRESOLVED_ATTACKER" identity
_UNRESOLVED_AGENT_ID = "UNRESOLVED_ATTACKER"
_UNRESOLVED_AGENT_NAME = "UNRESOLVED_ATTACKER"


def _has_adk_fields(metadata: Optional[Dict[str, Any]]) -> bool:
    """Return True if any meaningful ADK identity field is present in metadata."""
    if not metadata:
        return False
    adk_keys = {"agent_id", "agent_name", "agent_model", "thread_id"}
    return any(metadata.get(k) for k in adk_keys)


def _build_unresolved_identity() -> AttackerIdentity:
    """
    Construct a safe, deterministic fallback identity when extraction fails.

    Uses a fixed agent_id sentinel so the identity is recognisable in logs
    while still producing a valid SHA-256 fingerprint.
    """
    return AttackerIdentity(
        agent_id=_UNRESOLVED_AGENT_ID,
        agent_name=_UNRESOLVED_AGENT_NAME,
        primary_source=IdentitySource.SYSTEM_PROCESS,
    )


class AttackerIdentityExtractor:
    """
    Extracts ``AttackerIdentity`` instances from ADK tool call interception context.

    Resolution priority:
      1. ADK metadata (``agent_id``, ``agent_name``, ``agent_model``, ``thread_id``)
      2. Local process inspection (``os.getpid()``, ``os.getuid()``, ``psutil``)
      3. Degraded ``UNRESOLVED_ATTACKER`` sentinel on any unhandled exception

    Thread Safety:
      - Stateless: all resolution is performed in-call, no shared mutable state.
    """

    def extract(
        self,
        context: ToolCallContext,
        metadata: Optional[Dict[str, Any]],
    ) -> AttackerIdentity:
        """
        Extract an ``AttackerIdentity`` from the current interception context.

        Args:
            context:  The sanitized ``ToolCallContext`` from the interception pipeline.
            metadata: Raw ADK ``ToolCallContext.metadata`` dict (may be ``None``).

        Returns:
            A fully-populated ``AttackerIdentity`` with a computed SHA-256 fingerprint.
            On any extraction failure returns an ``UNRESOLVED_ATTACKER`` sentinel identity.
        """
        try:
            if _has_adk_fields(metadata):
                return self._extract_from_adk(metadata)  # type: ignore[arg-type]
            return self._extract_from_process()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "AttackerIdentityExtractor: extraction failed, returning UNRESOLVED_ATTACKER",
                exc_info=exc,
            )
            return _build_unresolved_identity()

    # ------------------------------------------------------------------
    # Internal extraction paths
    # ------------------------------------------------------------------

    def _extract_from_adk(self, metadata: Dict[str, Any]) -> AttackerIdentity:
        """
        Parse ADK agent identity fields from tool call metadata.

        Sets ``primary_source = ADK_METADATA``.
        """
        return AttackerIdentity(
            agent_id=metadata.get("agent_id"),
            agent_name=metadata.get("agent_name"),
            agent_model=metadata.get("agent_model"),
            thread_id=metadata.get("thread_id"),
            source_ip=metadata.get("source_ip"),
            container_id=metadata.get("container_id"),
            vault_token_accessor=metadata.get("vault_token_accessor"),
            primary_source=IdentitySource.ADK_METADATA,
        )

    def _extract_from_process(self) -> AttackerIdentity:
        """
        Inspect the current OS process for identity attributes.

        Sets ``primary_source = SYSTEM_PROCESS``.

        Falls back gracefully if ``psutil`` is unavailable or if OS calls fail
        (e.g. restricted environments, Windows UID absence).
        """
        pid: Optional[int] = None
        uid: Optional[int] = None
        process_name: Optional[str] = None
        cmdline: Optional[str] = None

        try:
            pid = os.getpid()
        except OSError:
            pass

        try:
            uid = os.getuid()  # type: ignore[attr-defined]  # Windows-safe
        except AttributeError:
            pass

        try:
            import psutil  # Local import — optional dependency, NFR-3 tolerant
            proc = psutil.Process(pid)
            process_name = proc.name()
            raw_cmdline = proc.cmdline()
            cmdline = " ".join(raw_cmdline) if raw_cmdline else None
        except Exception:  # noqa: BLE001
            # psutil may be unavailable or the process may have short-lived
            pass

        return AttackerIdentity(
            process_pid=pid,
            process_uid=uid,
            process_name=process_name,
            process_cmdline=cmdline,
            primary_source=IdentitySource.SYSTEM_PROCESS,
        )

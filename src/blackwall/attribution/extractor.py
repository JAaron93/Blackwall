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
import time
from typing import Any

from blackwall.attribution.linguistic import (
    GENERIC_COLLECTIVE_HANDLES,
    LinguisticSwarmClassifier,
)
from blackwall.models import AttackerIdentity, IdentitySource, ToolCallContext

logger = logging.getLogger(__name__)

# Sentinel values used for the degraded "UNRESOLVED_ATTACKER" identity
_UNRESOLVED_AGENT_ID = "UNRESOLVED_ATTACKER"
_UNRESOLVED_AGENT_NAME = "UNRESOLVED_ATTACKER"


def _has_adk_fields(metadata: dict[str, Any] | None) -> bool:
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

    def __init__(self, classifier: LinguisticSwarmClassifier | None = None) -> None:
        self.classifier = classifier or LinguisticSwarmClassifier()

    def extract(
        self,
        context: ToolCallContext,
        metadata: dict[str, Any] | None,
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
                identity = self._extract_from_adk(metadata)  # type: ignore[arg-type]
            else:
                identity = self._extract_from_process()

            # Linguistic Swarm Classification (TASK-2A.3, FR-1)
            markers = self.classifier.classify(context, metadata)
            identity.linguistic_markers = markers
            if markers.is_collective:
                identity.is_collective = True
                identity.collective_name = markers.collective_identity_inferred

            # False-monolith disambiguation with session-salted fingerprinting (FR-2)
            clean_id = (identity.agent_id or "").strip().lower()
            clean_name = (identity.agent_name or "").strip().lower()
            is_generic_handle = (
                clean_id in GENERIC_COLLECTIVE_HANDLES
                or clean_name in GENERIC_COLLECTIVE_HANDLES
                or any(token in clean_name for token in ("swarm", "collective", "hive"))
            )

            if identity.is_collective or is_generic_handle:
                identity.is_collective = True
                if not identity.collective_name:
                    identity.collective_name = markers.collective_identity_inferred or f"collective:{identity.agent_id or 'unknown'}"

                merged_meta = dict(context.metadata or {})
                if metadata:
                    merged_meta.update(metadata)

                session_id = (
                    merged_meta.get("session_id")
                    or merged_meta.get("session_salt")
                    or identity.thread_id
                    or f"epoch-{int(time.time() // 3600)}-pid-{identity.process_pid or os.getpid()}"
                )
                identity.session_salt = str(session_id)
                identity.identity_fingerprint = ""
                identity.compute_fingerprint()

            return identity
        except Exception as exc:
            logger.warning(
                "AttackerIdentityExtractor: extraction failed, returning UNRESOLVED_ATTACKER",
                exc_info=exc,
            )
            return _build_unresolved_identity()

    # ------------------------------------------------------------------
    # Internal extraction paths
    # ------------------------------------------------------------------

    def _extract_from_adk(self, metadata: dict[str, Any]) -> AttackerIdentity:
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
        pid: int | None = None
        uid: int | None = None
        process_name: str | None = None
        cmdline: str | None = None

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
        except Exception:  # noqa: BLE001, S110
            # psutil may be unavailable or the process may have short-lived
            pass

        return AttackerIdentity(
            process_pid=pid,
            process_uid=uid,
            process_name=process_name,
            process_cmdline=cmdline,
            primary_source=IdentitySource.SYSTEM_PROCESS,
        )

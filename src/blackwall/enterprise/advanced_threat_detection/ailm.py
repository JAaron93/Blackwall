"""AI-Induced Lateral Movement (AILM) Tracker for Blackwall Advanced Threat Detection (Pillar 6 Task 10)."""

from datetime import datetime
from typing import List, Set, Tuple

from blackwall.enterprise.advanced_threat_detection.models import (
    AILMEvidence,
    PermissionGrant,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.policy.models import PolicyConfig
from blackwall.validators import validate_temporal_sequence, validate_utc_datetime

# Predefined sensitive permission keywords
CRITICAL_PERMISSIONS = {
    "root",
    "sudo",
    "exfiltrate",
    "kernel_exec",
    "admin_exec",
    "bypass_auth",
    "dump_secrets",
}

# Recognized trust boundaries
TRUST_BOUNDARIES = {
    "user_space",
    "kernel_space",
    "sandbox",
    "host",
    "internal_api",
    "external_net",
    "external_network",
    "tenant_a",
    "tenant_b",
    "untrusted",
    "trusted",
    "public",
    "private",
}


class AILMTracker:
    """Tracks runtime permission grants and detects AI-Induced Lateral Movement across trust boundaries."""

    def __init__(
        self,
        store: AttackGraphStore | None = None,
        policy: PolicyConfig | None = None,
    ) -> None:
        self.store = store or AttackGraphStore(in_memory=True)
        self.policy = policy
        self._grants_by_agent: dict[str, list[PermissionGrant]] = {}

    async def track_permission_grant(self, grant: PermissionGrant) -> None:
        """Record a permission grant for an agent.

        Args:
            grant: Validated PermissionGrant instance.
        """
        # Ensure timestamp is UTC validated
        grant.timestamp = validate_utc_datetime(grant.timestamp)

        agent_id = grant.granted_to
        if agent_id not in self._grants_by_agent:
            self._grants_by_agent[agent_id] = []

        self._grants_by_agent[agent_id].append(grant)

    async def get_permission_grants(
        self,
        agent_id: str,
        time_window: Tuple[datetime, datetime] | None = None,
    ) -> List[PermissionGrant]:
        """Retrieve recorded permission grants for an agent, optionally within a time window.

        Args:
            agent_id: Identifier of grantee agent.
            time_window: Optional tuple of (start_time, end_time) UTC datetime filters.

        Returns:
            List of PermissionGrant instances matching filters.
        """
        grants = self._grants_by_agent.get(agent_id, [])
        if not time_window:
            return list(grants)

        start_raw, end_raw = time_window
        validate_temporal_sequence(
            start_raw, end_raw, start_name="start_time", end_name="end_time"
        )
        start_win = validate_utc_datetime(start_raw)
        end_win = validate_utc_datetime(end_raw)

        return [
            g for g in grants if start_win <= g.timestamp <= end_win
        ]

    async def identify_boundary_crossing(
        self, from_context: str, to_context: str
    ) -> bool:
        """Determine if a context transition crosses from one security boundary to another.

        Args:
            from_context: Source security context or scope.
            to_context: Target security context or scope.

        Returns:
            True if transition crosses a boundary, False otherwise.
        """
        from_norm = from_context.strip().lower()
        to_norm = to_context.strip().lower()

        if from_norm == to_norm:
            return False

        # If either context is in TRUST_BOUNDARIES or contexts differ, it's a boundary crossing
        return True

    def compute_risk_level(
        self, composed_permissions: Set[str], boundary_crossings: List[str]
    ) -> str:
        """Compute risk level classification (LOW, MEDIUM, HIGH, CRITICAL).

        Args:
            composed_permissions: Set of accumulated permissions.
            boundary_crossings: List of identified boundary crossing transitions.

        Returns:
            Risk level string: 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'.
        """
        num_crossings = len(boundary_crossings)
        has_critical_perm = any(
            p.lower() in CRITICAL_PERMISSIONS or any(cp in p.lower() for cp in CRITICAL_PERMISSIONS)
            for p in composed_permissions
        )

        if num_crossings >= 3 or (num_crossings >= 2 and has_critical_perm):
            return "CRITICAL"
        if num_crossings == 2 or (num_crossings == 1 and has_critical_perm) or (has_critical_perm and len(composed_permissions) >= 2):
            return "HIGH"
        if num_crossings == 1 or len(composed_permissions) >= 2:
            return "MEDIUM"
        return "LOW"

    async def detect_permission_composition(
        self,
        agent_id: str,
        time_window: Tuple[datetime, datetime],
    ) -> List[AILMEvidence]:
        """Detect agents accumulating multiple permissions over time or across trust boundaries.

        Args:
            agent_id: Identifier of agent to analyze.
            time_window: Tuple of (start_time, end_time) UTC datetime filters.

        Returns:
            List of AILMEvidence objects detected.
        """
        grants = await self.get_permission_grants(agent_id, time_window)
        if not grants:
            return []

        # Sort chronologically by timestamp
        grants = sorted(grants, key=lambda g: g.timestamp)

        composed_permissions: Set[str] = {g.permission for g in grants}

        # Track boundary crossings across consecutive grants or grant scopes
        boundary_crossings: List[str] = []
        for i in range(len(grants) - 1):
            curr_scope = grants[i].scope
            next_scope = grants[i + 1].scope
            if await self.identify_boundary_crossing(curr_scope, next_scope):
                transition = f"{curr_scope}->{next_scope}"
                if transition not in boundary_crossings:
                    boundary_crossings.append(transition)

        risk_level = self.compute_risk_level(composed_permissions, boundary_crossings)

        evidence = AILMEvidence(
            agent_id=agent_id,
            composed_permissions=composed_permissions,
            boundary_crossings=boundary_crossings,
            risk_level=risk_level,
        )

        return [evidence]

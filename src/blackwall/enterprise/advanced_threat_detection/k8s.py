"""Kubernetes Defense Layer for Blackwall Advanced Threat Detection (Pillar 6 Task 12)."""

from datetime import datetime, timezone
import re
from typing import Dict, List, Optional, Set, Tuple

from blackwall.enterprise.advanced_threat_detection.models import (
    K8sThreatEvidence,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.policy.models import PolicyConfig
from blackwall.validators import validate_temporal_sequence, validate_utc_datetime

TOKEN_PATH_PATTERN = r"/var/run/secrets/kubernetes.io/serviceaccount/token"
SECRET_API_PATTERN = r"/api/v1/(?:namespaces/[^/]+/)?secrets"


class KubernetesDefenseLayer:
    """Detects Kubernetes-specific threats including token theft, fleet spawning, secrets exfiltration, and self-respawning pods."""

    def __init__(
        self,
        store: AttackGraphStore | None = None,
        policy: PolicyConfig | None = None,
    ) -> None:
        self.store = store or AttackGraphStore(in_memory=True)
        self.policy = policy
        self._tracked_api_calls: Dict[str, List[NormalizedEvent]] = {}

    async def track_k8s_api_access(self, event: NormalizedEvent) -> None:
        """Track a Kubernetes API access event (successful or failed)."""
        event.timestamp = validate_utc_datetime(event.timestamp)
        agent_id = event.agent_id
        if agent_id not in self._tracked_api_calls:
            self._tracked_api_calls[agent_id] = []
        self._tracked_api_calls[agent_id].append(event)

    def get_tracked_api_calls(self, agent_id: str) -> List[NormalizedEvent]:
        """Retrieve tracked Kubernetes API access events for an agent."""
        return list(self._tracked_api_calls.get(agent_id, []))

    async def detect_pod_token_theft(
        self,
        agent_id: str | None = None,
        time_window: Tuple[datetime, datetime] | None = None,
    ) -> List[K8sThreatEvidence]:
        """Detect unauthorized access to service account token path /var/run/secrets/kubernetes.io/serviceaccount/token."""
        evidences: List[K8sThreatEvidence] = []
        if time_window:
            start_w, end_w = time_window
            validate_temporal_sequence(start_w, end_w)
            start_w = validate_utc_datetime(start_w)
            end_w = validate_utc_datetime(end_w)

        nodes = self.store._nodes.values() if hasattr(self.store, "_nodes") else []
        for node in nodes:
            event = node.event
            if agent_id and event.agent_id != agent_id:
                continue
            if time_window:
                if not (start_w <= event.timestamp <= end_w):
                    continue

            target_str = (event.target or "").lower()
            metadata_path = str(event.metadata.get("path") or "").lower()

            is_token_access = (
                TOKEN_PATH_PATTERN.lower() in target_str
                or TOKEN_PATH_PATTERN.lower() in metadata_path
                or "serviceaccount/token" in target_str
                or "serviceaccount/token" in metadata_path
            )

            if is_token_access:
                ns = str(event.metadata.get("namespace") or "default")
                pod = str(event.metadata.get("pod_name") or "unknown-pod")
                sa = str(event.metadata.get("service_account") or "default")
                evidence_data = {
                    "event_id": str(event.event_id),
                    "action": event.action,
                    "target": event.target,
                    "timestamp": event.timestamp.isoformat(),
                    "agent_id": event.agent_id,
                }
                evidences.append(
                    K8sThreatEvidence(
                        threat_type="pod_token_theft",
                        namespace=ns,
                        pod_name=pod,
                        service_account=sa,
                        evidence=evidence_data,
                    )
                )
        return evidences

    async def detect_fleet_spawning(
        self,
        time_window: Tuple[datetime, datetime] | None = None,
        min_pods: int = 10,
        min_nodes: int = 5,
        time_window_seconds: float = 60.0,
    ) -> List[K8sThreatEvidence]:
        """Detect rapid pod creation patterns across multiple nodes within a short time window."""
        evidences: List[K8sThreatEvidence] = []
        if time_window:
            start_w, end_w = time_window
            validate_temporal_sequence(start_w, end_w)
            start_w = validate_utc_datetime(start_w)
            end_w = validate_utc_datetime(end_w)

        nodes = self.store._nodes.values() if hasattr(self.store, "_nodes") else []
        spawn_events: List[NormalizedEvent] = []

        for node in nodes:
            event = node.event
            if time_window and not (start_w <= event.timestamp <= end_w):
                continue
            act = (event.action or "").lower()
            if act in {"create_pod", "spawn_pod", "pod_create", "sys_clone"} or "create" in act:
                spawn_events.append(event)

        if not spawn_events:
            return []

        spawn_events = sorted(spawn_events, key=lambda e: e.timestamp)
        created_pods: Set[str] = set()
        nodes_used: Set[str] = set()
        namespaces: Set[str] = set()
        service_accounts: Set[str] = set()

        for ev in spawn_events:
            pod_name = str(ev.metadata.get("pod_name") or ev.target)
            node_id = str(ev.metadata.get("node_id") or "node-default")
            ns = str(ev.metadata.get("namespace") or "default")
            sa = str(ev.metadata.get("service_account") or "default")
            created_pods.add(pod_name)
            nodes_used.add(node_id)
            namespaces.add(ns)
            service_accounts.add(sa)

        if len(created_pods) >= min_pods and len(nodes_used) >= min_nodes:
            ns_val = next(iter(namespaces)) if namespaces else "default"
            sa_val = next(iter(service_accounts)) if service_accounts else "default"
            evidences.append(
                K8sThreatEvidence(
                    threat_type="fleet_spawning",
                    namespace=ns_val,
                    pod_name=f"fleet-{len(created_pods)}-pods",
                    service_account=sa_val,
                    evidence={
                        "pod_count": len(created_pods),
                        "node_count": len(nodes_used),
                        "pod_list": list(created_pods),
                        "nodes": list(nodes_used),
                    },
                )
            )
        return evidences

    async def detect_secrets_exfiltration(
        self,
        agent_id: str | None = None,
        time_window: Tuple[datetime, datetime] | None = None,
        min_secret_reads: int = 5,
    ) -> List[K8sThreatEvidence]:
        """Detect bulk secret reads from Kubernetes API (tracking successful & failed calls)."""
        evidences: List[K8sThreatEvidence] = []
        if time_window:
            start_w, end_w = time_window
            validate_temporal_sequence(start_w, end_w)
            start_w = validate_utc_datetime(start_w)
            end_w = validate_utc_datetime(end_w)

        nodes = self.store._nodes.values() if hasattr(self.store, "_nodes") else []
        secret_events: List[NormalizedEvent] = []

        for node in nodes:
            event = node.event
            if agent_id and event.agent_id != agent_id:
                continue
            if time_window and not (start_w <= event.timestamp <= end_w):
                continue

            target_str = (event.target or "").lower()
            action_str = (event.action or "").lower()
            api_call = str(event.metadata.get("api_call") or "").lower()

            is_secret_read = (
                "secret" in target_str
                or "secret" in action_str
                or "secret" in api_call
                or bool(re.search(SECRET_API_PATTERN, target_str))
            )

            if is_secret_read:
                secret_events.append(event)
                await self.track_k8s_api_access(event)

        if len(secret_events) >= min_secret_reads:
            successful_calls = 0
            failed_calls = 0
            ns_val = "default"
            pod_val = "unknown-pod"
            sa_val = "default"

            for ev in secret_events:
                status_code = ev.metadata.get("status_code", 200)
                if isinstance(status_code, int) and status_code >= 400:
                    failed_calls += 1
                else:
                    successful_calls += 1
                if ev.metadata.get("namespace"):
                    ns_val = str(ev.metadata.get("namespace"))
                if ev.metadata.get("pod_name"):
                    pod_val = str(ev.metadata.get("pod_name"))
                if ev.metadata.get("service_account"):
                    sa_val = str(ev.metadata.get("service_account"))

            evidences.append(
                K8sThreatEvidence(
                    threat_type="secrets_exfiltration",
                    namespace=ns_val,
                    pod_name=pod_val,
                    service_account=sa_val,
                    evidence={
                        "total_calls": len(secret_events),
                        "successful_calls": successful_calls,
                        "failed_calls": failed_calls,
                        "agent_id": agent_id or (secret_events[0].agent_id if secret_events else "unknown"),
                    },
                )
            )

        return evidences

    async def detect_self_respawn(
        self,
        time_window: Tuple[datetime, datetime] | None = None,
    ) -> List[K8sThreatEvidence]:
        """Detect pods that automatically recreate themselves after termination (restart loops)."""
        evidences: List[K8sThreatEvidence] = []
        if time_window:
            start_w, end_w = time_window
            validate_temporal_sequence(start_w, end_w)
            start_w = validate_utc_datetime(start_w)
            end_w = validate_utc_datetime(end_w)

        nodes = self.store._nodes.values() if hasattr(self.store, "_nodes") else []
        pod_events: Dict[str, List[NormalizedEvent]] = {}

        for node in nodes:
            event = node.event
            if time_window and not (start_w <= event.timestamp <= end_w):
                continue
            act = (event.action or "").lower()
            if "pod" in act or "terminate" in act or "create" in act or "k8s://" in event.target:
                pod_name = str(event.metadata.get("pod_name") or event.target)
                if pod_name not in pod_events:
                    pod_events[pod_name] = []
                pod_events[pod_name].append(event)

        for pod_name, events in pod_events.items():
            sorted_events = sorted(events, key=lambda e: e.timestamp)
            terminations = 0
            creations = 0
            ns_val = "default"
            sa_val = "default"

            for ev in sorted_events:
                act = (ev.action or "").lower()
                status = str(ev.metadata.get("status") or "").lower()
                if "terminate" in act or status == "terminated":
                    terminations += 1
                elif "create" in act or status == "running":
                    creations += 1
                if ev.metadata.get("namespace"):
                    ns_val = str(ev.metadata.get("namespace"))
                if ev.metadata.get("service_account"):
                    sa_val = str(ev.metadata.get("service_account"))

            if terminations >= 1 and creations >= 1:
                evidences.append(
                    K8sThreatEvidence(
                        threat_type="self_respawning_pod",
                        namespace=ns_val,
                        pod_name=pod_name,
                        service_account=sa_val,
                        evidence={
                            "terminations": terminations,
                            "creations": creations,
                            "pod_name": pod_name,
                        },
                    )
                )

        return evidences

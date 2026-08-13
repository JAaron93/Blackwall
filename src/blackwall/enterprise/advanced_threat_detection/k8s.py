"""Kubernetes Defense Layer for Blackwall Advanced Threat Detection (Pillar 6 Task 12)."""

from datetime import datetime, timezone
import re
from typing import Dict, List, Optional, Set, Tuple

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    K8sThreatEvidence,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.policy.models import PolicyConfig
from blackwall.validators import validate_temporal_sequence, validate_utc_datetime

TOKEN_PATH_PATTERN = r"/var/run/secrets/kubernetes.io/serviceaccount/token"
K8S_SECRET_API_REGEX = re.compile(
    r"(?:/api/v1/|k8s://|kubernetes.*/api/v1/)(?:namespaces/[^/]+/)?secrets",
    re.IGNORECASE,
)


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

            is_authorized = (
                event.metadata.get("is_authorized") is True
                or event.metadata.get("authorized") is True
                or event.metadata.get("access_type") == "legitimate"
                or event.metadata.get("legitimate") is True
            )

            if is_token_access and not is_authorized:
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
        detected_windows: Set[Tuple[str, ...]] = set()

        for i in range(len(spawn_events)):
            window_events: List[NormalizedEvent] = []
            start_t = spawn_events[i].timestamp
            for j in range(i, len(spawn_events)):
                delta = (spawn_events[j].timestamp - start_t).total_seconds()
                if delta <= time_window_seconds:
                    window_events.append(spawn_events[j])
                else:
                    break

            created_pods: Set[str] = {
                str(ev.metadata.get("pod_name") or ev.target) for ev in window_events
            }
            nodes_used: Set[str] = {
                str(ev.metadata.get("node_id") or "node-default") for ev in window_events
            }
            namespaces: Set[str] = {
                str(ev.metadata.get("namespace") or "default") for ev in window_events
            }
            service_accounts: Set[str] = {
                str(ev.metadata.get("service_account") or "default") for ev in window_events
            }

            if len(created_pods) >= min_pods and len(nodes_used) >= min_nodes:
                pod_key = tuple(sorted(created_pods))
                if pod_key not in detected_windows:
                    detected_windows.add(pod_key)
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
                                "time_window_seconds": time_window_seconds,
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
        """Detect bulk secret reads strictly from Kubernetes API (tracking successful & failed calls)."""
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

            target_str = event.target or ""
            action_str = (event.action or "").lower()
            api_call = str(event.metadata.get("api_call") or "")

            if TOKEN_PATH_PATTERN in target_str or "/var/run/secrets" in target_str:
                continue

            is_k8s_api = (
                event.source in {EventSource.TOOL_CALL, EventSource.IDENTITY_ACCESS}
                or "kubernetes" in target_str.lower()
                or "k8s" in target_str.lower()
                or "/api/v1/" in target_str
                or bool(api_call)
            )

            is_secret_read = is_k8s_api and (
                bool(K8S_SECRET_API_REGEX.search(target_str))
                or bool(K8S_SECRET_API_REGEX.search(api_call))
                or (
                    action_str in {"get_secret", "list_secrets", "read_secret"}
                    and (
                        "secret" in target_str.lower()
                        or "secret" in api_call.lower()
                    )
                )
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
            has_been_terminated = False
            respawn_count = 0
            terminations = 0
            creations = 0
            ns_val = "default"
            sa_val = "default"

            for ev in sorted_events:
                act = (ev.action or "").lower()
                status = str(ev.metadata.get("status") or "").lower()
                if "terminate" in act or status == "terminated":
                    terminations += 1
                    has_been_terminated = True
                elif "create" in act or status == "running":
                    creations += 1
                    if has_been_terminated:
                        respawn_count += 1
                if ev.metadata.get("namespace"):
                    ns_val = str(ev.metadata.get("namespace"))
                if ev.metadata.get("service_account"):
                    sa_val = str(ev.metadata.get("service_account"))

            if respawn_count >= 1:
                evidences.append(
                    K8sThreatEvidence(
                        threat_type="self_respawning_pod",
                        namespace=ns_val,
                        pod_name=pod_name,
                        service_account=sa_val,
                        evidence={
                            "terminations": terminations,
                            "creations": creations,
                            "respawn_count": respawn_count,
                            "pod_name": pod_name,
                        },
                    )
                )

        return evidences

"""Unit tests for enterprise Advanced Threat Detection data models and field/model validators."""

from datetime import UTC, datetime, timedelta, timezone
import math
from typing import Any
from uuid import UUID, uuid1, uuid4

import pytest
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    EventSource,
    ExploitCategory,
    InboundMethodType,
    InboundProtocolType,
    InjectionSourceType,
    ReactionActionType,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    ActiveReactionPayload,
    AgentQuotaUsage,
    AILMEvidence,
    Alert,
    AttackNode,
    AttackPath,
    C2Evidence,
    ExploitChainEvidence,
    InboundProtocolMessage,
    K8sThreatEvidence,
    NormalizedEvent,
    PermissionGrant,
    PromptInjectionEvidence,
    RegistryThreatEvidence,
    SwarmEvidence,
)


# ==============================================================================
# Helper Factories
# ==============================================================================


def create_normalized_event(
    event_id: Any = None,
    timestamp: Any = None,
    source: EventSource = EventSource.TOOL_CALL,
    agent_id: str = "agent-alpha",
    action: str = "invoke_tool",
    target: str = "code_executor",
    metadata: dict = None,
    risk_score: float = 0.5,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id if event_id is not None else uuid4(),
        timestamp=timestamp if timestamp is not None else datetime.now(timezone.utc),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata if metadata is not None else {},
        risk_score=risk_score,
    )


# ==============================================================================
# 1. NormalizedEvent and AttackNode Validators
# ==============================================================================


class TestNormalizedEventAndAttackNode:
    def test_normalized_event_valid_and_serialization(self):
        ev_id = uuid4()
        now = datetime.now(timezone.utc)
        ev = create_normalized_event(event_id=ev_id, timestamp=now, risk_score=0.85)
        assert ev.event_id == ev_id
        assert ev.timestamp == now
        assert ev.risk_score == 0.85
        assert NormalizedEvent(**ev.model_dump()) == ev

    @pytest.mark.parametrize("invalid_uuid", ["not-uuid", str(uuid1()), "12345", ""])
    def test_normalized_event_invalid_uuid(self, invalid_uuid):
        with pytest.raises((ValidationError, ValueError)):
            create_normalized_event(event_id=invalid_uuid)

    def test_normalized_event_invalid_timestamp(self):
        naive = datetime.now()
        with pytest.raises((ValidationError, ValueError)):
            create_normalized_event(timestamp=naive)

        est = timezone(timedelta(hours=-5))
        with pytest.raises((ValidationError, ValueError)):
            create_normalized_event(timestamp=datetime.now(est))

    @pytest.mark.parametrize("invalid_agent_id", ["", "   ", "\t\n"])
    def test_normalized_event_invalid_agent_id(self, invalid_agent_id):
        with pytest.raises((ValidationError, ValueError)):
            create_normalized_event(agent_id=invalid_agent_id)

    @pytest.mark.parametrize("invalid_risk", [-0.1, 1.1, 5.0])
    def test_normalized_event_invalid_risk_score(self, invalid_risk):
        with pytest.raises((ValidationError, ValueError)):
            create_normalized_event(risk_score=invalid_risk)

    def test_attack_node_valid_and_edges(self):
        ev = create_normalized_event()
        node_id = uuid4()
        edge1, edge2 = uuid4(), uuid4()
        node = AttackNode(
            node_id=node_id,
            event=ev,
            incoming_edges=[edge1],
            outgoing_edges=[edge2],
        )
        assert node.node_id == node_id
        assert node.event == ev
        assert node.incoming_edges == [edge1]
        assert node.outgoing_edges == [edge2]
        assert AttackNode(**node.model_dump()) == node


# ==============================================================================
# 2. AttackPath and SwarmEvidence (Min Collections & Temporal Ordering)
# ==============================================================================


class TestAttackPathAndSwarmEvidence:
    def test_attack_path_valid(self):
        now = datetime.now(timezone.utc)
        node1 = AttackNode(node_id=uuid4(), event=create_normalized_event(timestamp=now))
        node2 = AttackNode(node_id=uuid4(), event=create_normalized_event(timestamp=now + timedelta(seconds=5)))
        path = AttackPath(
            path_id=uuid4(),
            agent_id="agent-01",
            nodes=[node1, node2],
            start_time=now,
            end_time=now + timedelta(seconds=10),
            risk_score=0.9,
            attack_stages=["discovery", "execution"],
            correlation_score=0.95,
        )
        assert len(path.nodes) == 2
        assert path.risk_score == 0.9
        assert AttackPath(**path.model_dump()) == path

    def test_attack_path_min_nodes_rejection(self):
        now = datetime.now(timezone.utc)
        node1 = AttackNode(node_id=uuid4(), event=create_normalized_event())
        with pytest.raises(ValidationError, match="at least 2"):
            AttackPath(
                path_id=uuid4(),
                agent_id="agent-01",
                nodes=[node1],
                start_time=now,
                end_time=now,
                risk_score=0.5,
                correlation_score=0.5,
            )

        with pytest.raises(ValidationError, match="at least 2"):
            AttackPath(
                path_id=uuid4(),
                agent_id="agent-01",
                nodes=[],
                start_time=now,
                end_time=now,
                risk_score=0.5,
                correlation_score=0.5,
            )

    def test_attack_path_temporal_ordering_violation(self):
        now = datetime.now(timezone.utc)
        node1 = AttackNode(node_id=uuid4(), event=create_normalized_event())
        node2 = AttackNode(node_id=uuid4(), event=create_normalized_event())
        with pytest.raises(ValidationError, match="greater than or equal to"):
            AttackPath(
                path_id=uuid4(),
                agent_id="agent-01",
                nodes=[node1, node2],
                start_time=now,
                end_time=now - timedelta(seconds=1),
                risk_score=0.5,
                correlation_score=0.5,
            )

    def test_swarm_evidence_valid(self):
        now = datetime.now(timezone.utc)
        swarm = SwarmEvidence(
            swarm_id=uuid4(),
            agent_ids={"agent-1", "agent-2", "agent-3"},
            shared_patterns=["credential_probing"],
            temporal_correlation=0.88,
            coordination_score=0.92,
            first_seen=now,
            last_seen=now + timedelta(minutes=15),
        )
        assert len(swarm.agent_ids) == 3
        assert SwarmEvidence(**swarm.model_dump()) == swarm

    def test_swarm_evidence_min_agents_rejection(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError, match="at least 2"):
            SwarmEvidence(
                swarm_id=uuid4(),
                agent_ids={"lone-agent"},
                temporal_correlation=0.5,
                coordination_score=0.5,
                first_seen=now,
                last_seen=now,
            )

    def test_swarm_evidence_temporal_sequence_violation(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError, match="greater than or equal to"):
            SwarmEvidence(
                swarm_id=uuid4(),
                agent_ids={"agent-1", "agent-2"},
                temporal_correlation=0.5,
                coordination_score=0.5,
                first_seen=now,
                last_seen=now - timedelta(seconds=5),
            )


# ==============================================================================
# 3. Evidence Models: ExploitChain, PermissionGrant, AILM, C2, K8s, Registry
# ==============================================================================


class TestEvidenceModels:
    def test_exploit_chain_evidence_valid_and_bounds(self):
        chain_id = uuid4()
        evidence = ExploitChainEvidence(
            chain_id=chain_id,
            exploits=[
                ("CVE-2026-1001", ExploitCategory.RCE),
                ("CVE-2026-1002", ExploitCategory.PRIVILEGE_ESCALATION),
            ],
            novelty_score=0.95,
            chaining_confidence=0.85,
        )
        assert evidence.chain_id == chain_id
        assert len(evidence.exploits) == 2
        assert ExploitChainEvidence(**evidence.model_dump()) == evidence

        with pytest.raises(ValidationError):
            ExploitChainEvidence(chain_id=chain_id, novelty_score=-0.1, chaining_confidence=0.5)

    def test_permission_grant_valid_and_uuid_checks(self):
        grant_id = uuid4()
        by_id = uuid4()
        to_id = uuid4()
        now = datetime.now(timezone.utc)
        grant = PermissionGrant(
            grant_id=grant_id,
            permission="storage.buckets.read",
            granted_by=by_id,
            granted_to=to_id,
            timestamp=now,
            scope="project/production",
        )
        assert grant.grant_id == grant_id
        assert grant.granted_by == by_id
        assert grant.granted_to == to_id
        assert grant.permission == "storage.buckets.read"
        assert grant.scope == "project/production"
        assert PermissionGrant(**grant.model_dump()) == grant

    @pytest.mark.parametrize("invalid_uuid", ["not-uuid", str(uuid1()), ""])
    def test_permission_grant_invalid_uuids(self, invalid_uuid):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError):
            PermissionGrant(
                grant_id=invalid_uuid,
                permission="read",
                granted_by=uuid4(),
                granted_to=uuid4(),
                timestamp=now,
                scope="scope",
            )

        with pytest.raises(ValidationError):
            PermissionGrant(
                grant_id=uuid4(),
                permission="read",
                granted_by=invalid_uuid,
                granted_to=uuid4(),
                timestamp=now,
                scope="scope",
            )

        with pytest.raises(ValidationError):
            PermissionGrant(
                grant_id=uuid4(),
                permission="read",
                granted_by=uuid4(),
                granted_to=invalid_uuid,
                timestamp=now,
                scope="scope",
            )

    @pytest.mark.parametrize("empty_val", ["", "   ", "\t"])
    def test_permission_grant_empty_strings(self, empty_val):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError):
            PermissionGrant(
                grant_id=uuid4(),
                permission=empty_val,
                granted_by=uuid4(),
                granted_to=uuid4(),
                timestamp=now,
                scope="scope",
            )

        with pytest.raises(ValidationError):
            PermissionGrant(
                grant_id=uuid4(),
                permission="perm",
                granted_by=uuid4(),
                granted_to=uuid4(),
                timestamp=now,
                scope=empty_val,
            )

    def test_ailm_evidence_valid(self):
        ailm = AILMEvidence(
            agent_id="agent-007",
            composed_permissions={"read:db", "write:s3"},
            boundary_crossings=["internal-vpc", "public-dmz"],
            risk_level="HIGH",
        )
        assert ailm.agent_id == "agent-007"
        assert len(ailm.composed_permissions) == 2
        assert AILMEvidence(**ailm.model_dump()) == ailm

    def test_c2_evidence_valid(self):
        c2 = C2Evidence(
            agent_id="agent-c2",
            c2_endpoints=["https://evil-c2.example.com/beacon"],
            communication_pattern="periodic_heartbeat_jitter",
            persistence_indicators=["systemd_service_drop"],
        )
        assert c2.communication_pattern == "periodic_heartbeat_jitter"
        assert C2Evidence(**c2.model_dump()) == c2

    def test_k8s_threat_evidence_valid(self):
        k8s = K8sThreatEvidence(
            threat_type="service_account_token_theft",
            namespace="kube-system",
            pod_name="sidecar-worker-x9",
            service_account="cluster-admin-sa",
            evidence={"extracted_jwt": True, "destination_ip": "10.0.0.99"},
        )
        assert k8s.namespace == "kube-system"
        assert K8sThreatEvidence(**k8s.model_dump()) == k8s

    def test_registry_threat_evidence_valid(self):
        reg = RegistryThreatEvidence(
            registry_type="pypi",
            package_name="blackwall-fake-plugin",
            exploit_indicators=["obfuscated_setup_py"],
            cve_candidates=["CVE-2026-9999"],
            probing_event_count=3,
            event_ids=["ev-1", "ev-2", "ev-3"],
        )
        assert reg.probing_event_count == 3
        assert RegistryThreatEvidence(**reg.model_dump()) == reg


# ==============================================================================
# 4. Alert and ActiveReactionPayload
# ==============================================================================


class TestAlertAndReactionPayload:
    def test_alert_valid_and_serialization(self):
        alert_id = uuid4()
        evidence_id = uuid4()
        now = datetime.now(timezone.utc)
        alert = Alert(
            alert_id=alert_id,
            timestamp=now,
            severity=AlertSeverity.CRITICAL,
            threat_type="SwarmExploit",
            title="Coordinated swarm attack detected",
            description="3 agents coordinating on lateral movement",
            evidence_id=evidence_id,
            agent_id="agent-01",
            agent_ids=["agent-01", "agent-02", "agent-03"],
            evidence={"confidence": 0.98},
            metadata={"source": "correlator"},
        )
        assert alert.alert_id == alert_id
        assert alert.evidence_id == evidence_id
        assert alert.severity == AlertSeverity.CRITICAL
        assert Alert(**alert.model_dump()) == alert

    def test_alert_evidence_id_nullable(self):
        alert = Alert(
            severity=AlertSeverity.LOW,
            threat_type="PortScan",
            title="Reconnaissance detected",
            description="Single port scan observed",
            evidence_id=None,
        )
        assert alert.evidence_id is None

    @pytest.mark.parametrize("empty_str", ["", "   "])
    def test_alert_empty_string_rejection(self, empty_str):
        with pytest.raises(ValidationError):
            Alert(
                severity=AlertSeverity.HIGH,
                threat_type=empty_str,
                title="Title",
                description="Desc",
            )
        with pytest.raises(ValidationError):
            Alert(
                severity=AlertSeverity.HIGH,
                threat_type="Threat",
                title=empty_str,
                description="Desc",
            )
        with pytest.raises(ValidationError):
            Alert(
                severity=AlertSeverity.HIGH,
                threat_type="Threat",
                title="Title",
                description=empty_str,
            )

    def test_active_reaction_payload_valid(self):
        reaction_id = uuid4()
        trigger_id = uuid4()
        payload = ActiveReactionPayload(
            reaction_id=reaction_id,
            trigger_evidence_id=trigger_id,
            target_agent_id="rogue-agent-77",
            target_pid=4321,
            target_ip="192.168.1.100",
            action_type=ReactionActionType.EBPF_DROP,
            evaluation_env_id="eval-sandbox_01",
            status="EXECUTED",
            execution_duration_ms=4.2,
        )
        assert payload.reaction_id == reaction_id
        assert payload.target_pid == 4321
        assert payload.target_ip == "192.168.1.100"
        assert payload.evaluation_env_id == "eval-sandbox_01"
        assert ActiveReactionPayload(**payload.model_dump()) == payload

    @pytest.mark.parametrize("invalid_pid", [0, -1, -500])
    def test_active_reaction_payload_invalid_pid(self, invalid_pid):
        with pytest.raises(ValidationError, match="greater than 0"):
            ActiveReactionPayload(
                trigger_evidence_id=uuid4(),
                target_agent_id="agent-01",
                target_pid=invalid_pid,
                action_type=ReactionActionType.EBPF_DROP,
            )

    @pytest.mark.parametrize("valid_ip", ["10.0.0.1", "127.0.0.1", "2001:db8::1", "::1"])
    def test_active_reaction_payload_valid_ip(self, valid_ip):
        payload = ActiveReactionPayload(
            trigger_evidence_id=uuid4(),
            target_agent_id="agent-01",
            target_ip=valid_ip,
            action_type=ReactionActionType.EBPF_DROP,
        )
        assert payload.target_ip == valid_ip

    @pytest.mark.parametrize("invalid_ip", ["999.999.999.999", "not-an-ip", "10.0.0.1.5", "", "   "])
    def test_active_reaction_payload_invalid_ip(self, invalid_ip):
        with pytest.raises(ValidationError):
            ActiveReactionPayload(
                trigger_evidence_id=uuid4(),
                target_agent_id="agent-01",
                target_ip=invalid_ip,
                action_type=ReactionActionType.EBPF_DROP,
            )

    @pytest.mark.parametrize("valid_env_id", ["eval-1", "sandbox_test-02", "ENV123"])
    def test_active_reaction_payload_valid_eval_env_id(self, valid_env_id):
        payload = ActiveReactionPayload(
            trigger_evidence_id=uuid4(),
            target_agent_id="agent-01",
            action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
            evaluation_env_id=valid_env_id,
        )
        assert payload.evaluation_env_id == valid_env_id

    @pytest.mark.parametrize("invalid_env_id", ["eval env", "env@bad", "env#1", "", "   "])
    def test_active_reaction_payload_invalid_eval_env_id(self, invalid_env_id):
        with pytest.raises(ValidationError):
            ActiveReactionPayload(
                trigger_evidence_id=uuid4(),
                target_agent_id="agent-01",
                action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
                evaluation_env_id=invalid_env_id,
            )


# ==============================================================================
# 5. InboundProtocolMessage, PromptInjectionEvidence, AgentQuotaUsage
# ==============================================================================


class TestProtocolInjectionAndQuota:
    def test_inbound_protocol_message_valid(self):
        msg_id = uuid4()
        now = datetime.now(timezone.utc)
        msg = InboundProtocolMessage(
            message_id=msg_id,
            sender_id="sender-agent",
            recipient_agent_id="receiver-agent",
            protocol=InboundProtocolType.MCP_SSE,
            method=InboundMethodType.TOOLS_CALL,
            payload={"tool": "read_file", "params": {"path": "/etc/passwd"}},
            timestamp=now,
        )
        assert msg.message_id == msg_id
        assert msg.sender_id == "sender-agent"
        assert msg.payload == {"tool": "read_file", "params": {"path": "/etc/passwd"}}
        assert InboundProtocolMessage(**msg.model_dump()) == msg

    def test_inbound_protocol_message_empty_payload_rejected(self):
        with pytest.raises(ValidationError):
            InboundProtocolMessage(
                sender_id="s1",
                recipient_agent_id="r1",
                protocol=InboundProtocolType.A2A_REST,
                method=InboundMethodType.PROMPT_SUBMIT,
                payload={},
            )

    def test_prompt_injection_evidence_valid(self):
        scan_id = uuid4()
        pie = PromptInjectionEvidence(
            scan_id=scan_id,
            source_context=InjectionSourceType.GIT_DIFF,
            detected_patterns=["ignore previous instructions", "system override"],
            injection_confidence=0.98,
            sanitized_content="[SANITIZED_DIFF_PAYLOAD]",
        )
        assert pie.scan_id == scan_id
        assert len(pie.detected_patterns) == 2
        assert pie.injection_confidence == 0.98
        assert PromptInjectionEvidence(**pie.model_dump()) == pie

    def test_prompt_injection_evidence_min_patterns_rejected(self):
        with pytest.raises(ValidationError, match="at least 1"):
            PromptInjectionEvidence(
                source_context=InjectionSourceType.WEB_SCRAPE,
                detected_patterns=[],
                injection_confidence=0.5,
                sanitized_content="clean",
            )

    @pytest.mark.parametrize("empty_content", ["", "   ", "\t"])
    def test_prompt_injection_evidence_empty_sanitized_content_rejected(self, empty_content):
        with pytest.raises(ValidationError):
            PromptInjectionEvidence(
                source_context=InjectionSourceType.INCOMING_A2A_MSG,
                detected_patterns=["pattern1"],
                injection_confidence=0.7,
                sanitized_content=empty_content,
            )

    def test_agent_quota_usage_valid(self):
        now = datetime.now(timezone.utc)
        quota = AgentQuotaUsage(
            agent_id="worker-01",
            time_window_start=now,
            tokens_consumed=15000,
            api_call_count=120,
            token_burn_rate_per_sec=250.5,
            quota_exceeded=False,
        )
        assert quota.agent_id == "worker-01"
        assert quota.tokens_consumed == 15000
        assert quota.token_burn_rate_per_sec == 250.5
        assert AgentQuotaUsage(**quota.model_dump()) == quota

    @pytest.mark.parametrize("invalid_count", [-1, -100, "not-a-number", [1, 2], {"count": 1}])
    def test_agent_quota_usage_invalid_counts(self, invalid_count):
        with pytest.raises(ValidationError):
            AgentQuotaUsage(
                agent_id="w1",
                tokens_consumed=invalid_count,
                api_call_count=10,
                token_burn_rate_per_sec=1.0,
                quota_exceeded=False,
            )

        with pytest.raises(ValidationError):
            AgentQuotaUsage(
                agent_id="w1",
                tokens_consumed=100,
                api_call_count=invalid_count,
                token_burn_rate_per_sec=1.0,
                quota_exceeded=False,
            )

    @pytest.mark.parametrize("invalid_rate", [-0.1, -10.0, float("nan"), float("inf"), "not-a-float"])
    def test_agent_quota_usage_invalid_burn_rate(self, invalid_rate):
        with pytest.raises(ValidationError):
            AgentQuotaUsage(
                agent_id="w1",
                tokens_consumed=10,
                api_call_count=1,
                token_burn_rate_per_sec=invalid_rate,
                quota_exceeded=False,
            )

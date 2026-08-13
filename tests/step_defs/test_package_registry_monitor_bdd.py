"""BDD Step Definitions for Package Registry Monitor (`tests/features/package_registry_monitor.feature`)."""

from datetime import datetime, timedelta, timezone
import uuid
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    NormalizedEvent,
    RegistryThreatEvidence,
)
from blackwall.enterprise.advanced_threat_detection.registry import (
    PackageRegistryMonitor,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from tests.step_defs.async_utils import run_async

scenarios("../features/package_registry_monitor.feature")


class RegistryBDDState:
    def __init__(self):
        self.store = AttackGraphStore(in_memory=True)
        self.monitor = PackageRegistryMonitor(store=self.store)
        self.agent_id = None
        self.time_window = None
        self.evidences = []
        self.evidence_obj = None


@pytest.fixture
def registry_state():
    return RegistryBDDState()


def create_pkg_event(
    agent_id: str,
    action: str,
    target: str,
    offset_seconds: float = 0.0,
    metadata: dict = None,
    source: EventSource = EventSource.PIPELINE_EXECUTION,
) -> NormalizedEvent:
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=offset_seconds),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata or {},
        risk_score=0.8,
    )


# Scenario 1
@given(
    parsers.parse(
        'an agent "{agent_id}" issuing a malformed package request "{url}" with prototype pollution payload'
    )
)
def given_malformed_npm_request(registry_state, agent_id, url):
    registry_state.agent_id = agent_id
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    registry_state.time_window = (base_time, base_time + timedelta(minutes=10))

    event = create_pkg_event(
        agent_id=agent_id,
        action="POST",
        target=url,
        offset_seconds=5.0,
        metadata={
            "registry_type": "npm",
            "package_name": "__proto__",
            "payload": '{"__proto__": {"admin": true}}',
            "url": url,
        },
    )
    run_async(registry_state.store.insert_event(event))


@when(
    parsers.parse(
        'the package registry monitor runs exploit probing detection for "{agent_id}"'
    )
)
def when_run_exploit_probing(registry_state, agent_id):
    registry_state.evidences = run_async(
        registry_state.monitor.detect_exploit_probing(
            agent_id=agent_id, time_window=registry_state.time_window
        )
    )


@then(
    parsers.parse(
        'registry threat evidence should be generated with registry_type "{expected_type}" and an exploit indicator'
    )
)
def then_check_npm_evidence(registry_state, expected_type):
    assert len(registry_state.evidences) >= 1
    ev = registry_state.evidences[0]
    assert ev.registry_type.lower() == expected_type.lower()
    assert len(ev.exploit_indicators) >= 1


# Scenario 2
@given(
    parsers.parse(
        'an agent "{agent_id}" generating 8 consecutive 404 responses across nonexistent packages on "{registry_url}"'
    )
)
def given_unusual_pypi_404_events(registry_state, agent_id, registry_url):
    registry_state.agent_id = agent_id
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    registry_state.time_window = (base_time, base_time + timedelta(minutes=10))

    for i in range(8):
        event = create_pkg_event(
            agent_id=agent_id,
            action="GET",
            target=f"{registry_url}/pypi/fake-pkg-{i}/json",
            offset_seconds=float(i * 2),
            metadata={
                "registry_type": "PyPI",
                "package_name": f"fake-pkg-{i}",
                "status_code": 404,
                "url": f"{registry_url}/pypi/fake-pkg-{i}/json",
            },
        )
        run_async(registry_state.store.insert_event(event))


@then(
    parsers.parse(
        'registry threat evidence should be generated for "{expected_type}" identifying unusual scanning activity'
    )
)
def then_check_pypi_evidence(registry_state, expected_type):
    assert len(registry_state.evidences) >= 1
    ev = registry_state.evidences[0]
    assert ev.registry_type.lower() == expected_type.lower()
    assert any("404" in ind.lower() or "scanning" in ind.lower() for ind in ev.exploit_indicators)


# Scenario 3
@given(
    parsers.parse(
        'a detected registry threat evidence object for registry_type "{reg_type}" and package "{pkg}"'
    )
)
def given_registry_evidence_obj(registry_state, reg_type, pkg):
    registry_state.evidence_obj = RegistryThreatEvidence(
        registry_type=reg_type,
        package_name=pkg,
        exploit_indicators=["Path traversal detected in package request"],
        cve_candidates=["CVE-2020-7980"],
    )


@when("inspecting the RegistryThreatEvidence model")
def when_inspect_registry_evidence_model(registry_state):
    pass


@then(
    parsers.parse(
        'it should contain the registry_type "{expected_type}" and package_name "{expected_pkg}"'
    )
)
def then_check_evidence_model_fields(registry_state, expected_type, expected_pkg):
    ev = registry_state.evidence_obj
    assert ev.registry_type == expected_type
    assert ev.package_name == expected_pkg


# Scenario 4
@given(
    parsers.parse(
        'an agent "{agent_id}" sending a request containing JNDI lookup "{payload}" to "{url}"'
    )
)
def given_cve_pattern_request(registry_state, agent_id, payload, url):
    registry_state.agent_id = agent_id
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    registry_state.time_window = (base_time, base_time + timedelta(minutes=10))

    event = create_pkg_event(
        agent_id=agent_id,
        action="GET",
        target=url,
        offset_seconds=5.0,
        metadata={
            "registry_type": "Artifactory",
            "package_name": "log4j-core",
            "query": payload,
            "url": url,
        },
    )
    run_async(registry_state.store.insert_event(event))


@then(
    parsers.parse(
        'the generated registry threat evidence should populate cve_candidates containing "{expected_cve}"'
    )
)
def then_check_cve_candidates(registry_state, expected_cve):
    assert len(registry_state.evidences) >= 1
    ev = registry_state.evidences[0]
    assert any(expected_cve in cve for cve in ev.cve_candidates)

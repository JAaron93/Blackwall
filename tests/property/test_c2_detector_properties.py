"""Property-based tests for C2InfrastructureDetector using Hypothesis (Pillar 6 Task 11 / Properties 41-45)."""

from datetime import datetime, timedelta, timezone
import uuid

from hypothesis import given, settings, strategies as st
import pytest

from blackwall.enterprise.advanced_threat_detection import (
    C2Evidence,
    C2InfrastructureDetector,
    EventSource,
    NormalizedEvent,
)


# Property 41: C2 Endpoint Detection
@pytest.mark.asyncio
@given(
    c2_domain=st.sampled_from([
        "requestbin.net",
        "requestbin.com",
        "pastebin.com",
        "gist.github.com",
        "hastebin.com",
        "justpaste.it",
        "rentry.co",
        "ghostbin.com",
        "webhook.site",
        "sub.pipedream.net",
        "sub.pipedream.com",
        "sub.ngrok.io",
        "sub.ngrok-free.app",
        "sub.localtunnel.me",
        "serveo.net",
        "pagekite.me",
        "discord.com/api/webhooks",
        "hooks.slack.com",
        "mybucket.s3.amazonaws.com",
        "storage.googleapis.com",
        "myaccount.blob.core.windows.net",
        "dropbox.com",
        "mega.nz",
        "drive.google.com",
    ]),
    scheme=st.sampled_from(["http://", "https://", ""]),
    path=st.sampled_from(["", "/api/v1/test", "/raw/abcdef", "?id=123&token=xyz"]),
)
@settings(max_examples=30)
async def test_property_41_c2_endpoint_detection_valid_c2(
    c2_domain: str, scheme: str, path: str
):
    """Property 41: Valid C2 URLs MUST always be classified to a non-None service type."""
    detector = C2InfrastructureDetector()
    url = f"{scheme}{c2_domain}{path}"
    service_type = await detector.classify_endpoint(url)
    assert service_type is not None
    assert service_type in {
        "requestbin",
        "pastebin",
        "github_gist",
        "webhook_receiver",
        "cloud_storage",
    }


@pytest.mark.asyncio
@given(
    benign_domain=st.sampled_from([
        "example.com",
        "google.com",
        "github.com",
        "example.org",
        "wikipedia.org",
        "internal.corp.local",
        "127.0.0.1",
        "localhost",
        "my-api.custom-domain.com",
        "stackoverflow.com",
        "pypi.org",
    ]),
    scheme=st.sampled_from(["http://", "https://", ""]),
    path=st.sampled_from(["", "/index.html", "/search?q=python", "/users/profile"]),
)
@settings(max_examples=30)
async def test_property_41_c2_endpoint_detection_benign(
    benign_domain: str, scheme: str, path: str
):
    """Property 41: Benign domains MUST be classified as None."""
    detector = C2InfrastructureDetector()
    url = f"{scheme}{benign_domain}{path}"
    service_type = await detector.classify_endpoint(url)
    assert service_type is None


# Property 42: Beaconing Pattern Detection
@pytest.mark.asyncio
@given(
    num_events=st.integers(min_value=3, max_value=8),
    interval_sec=st.floats(min_value=10.0, max_value=120.0),
    agent_id=st.text(min_size=1, max_size=15).filter(lambda s: bool(s.strip())),
    endpoint=st.sampled_from(["c2-server.com", "webhook.site", "10.0.0.5"]),
)
@settings(max_examples=30)
async def test_property_42_beaconing_pattern_detection(
    num_events: int, interval_sec: float, agent_id: str, endpoint: str
):
    """Property 42: Periodic timestamp sequences with CV <= 0.25 MUST be detected as beaconing."""
    detector = C2InfrastructureDetector()
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    current_time = base_time
    for i in range(num_events):
        e = NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=current_time,
            source=EventSource.KERNEL_SYSCALL,
            agent_id=agent_id,
            action="network_connect",
            target=endpoint,
            metadata={"domain": endpoint},
            risk_score=0.5,
        )
        detector.record_event(e)
        # Add interval with slight variation (< 5% variation so CV <= 0.25)
        jitter = (i % 3 - 1) * (0.02 * interval_sec)
        current_time += timedelta(seconds=interval_sec + jitter)

    start_win = base_time - timedelta(seconds=10)
    end_win = current_time + timedelta(seconds=10)

    is_beaconing = await detector.detect_beaconing(
        agent_id, endpoint, (start_win, end_win)
    )
    assert is_beaconing is True


# Property 43: C2 Communication Pattern Classification
@pytest.mark.asyncio
@given(
    target=st.sampled_from([
        "webhook.site",
        "s3.amazonaws.com",
        "pastebin.com",
        "gist.github.com",
        "requestbin.net",
        "custom-c2-server.org",
    ]),
    agent_id=st.text(min_size=1, max_size=15).filter(lambda s: bool(s.strip())),
)
@settings(max_examples=30)
async def test_property_43_c2_communication_pattern_classification(
    target: str, agent_id: str
):
    """Property 43: Communication pattern MUST be one of 'beaconing', 'polling', 'webhook', 'exfiltration', or 'interactive'."""
    detector = C2InfrastructureDetector()
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    e = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=10),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="connect",
        target=target,
        metadata={},
        risk_score=0.7,
    )
    detector.record_event(e)

    time_win = (base_time, base_time + timedelta(seconds=60))
    evidences = await detector.detect_c2_establishment(agent_id, time_win)

    if evidences:
        for ev in evidences:
            assert isinstance(ev, C2Evidence)
            assert ev.communication_pattern in {
                "beaconing",
                "polling",
                "webhook",
                "exfiltration",
                "interactive",
            }


# Property 44: C2 Persistence Indicator Identification
@pytest.mark.asyncio
@given(
    keyword=st.sampled_from([
        "cron",
        "crontab",
        "/etc/cron",
        "systemd",
        "systemctl",
        "schtasks",
        "taskschd",
        "launchctl",
        "respawn",
        "while true",
        "restart=always",
        "supervisord",
    ]),
    target_field=st.sampled_from(["action", "target", "metadata_val"]),
    agent_id=st.text(min_size=1, max_size=15).filter(lambda s: bool(s.strip())),
)
@settings(max_examples=30)
async def test_property_44_c2_persistence_indicator_identification(
    keyword: str, target_field: str, agent_id: str
):
    """Property 44: Events with cron/systemd/respawn keywords MUST return non-empty persistence indicators."""
    detector = C2InfrastructureDetector()
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    action = "exec"
    target = "/bin/sh"
    metadata = {}

    if target_field == "action":
        action = f"install_{keyword}"
    elif target_field == "target":
        target = f"/path/to/{keyword}"
    else:
        metadata = {"command": f"run {keyword}"}

    e = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=10),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata,
        risk_score=0.8,
    )
    detector.record_event(e)

    time_win = (base_time, base_time + timedelta(seconds=60))
    indicators = await detector.detect_persistence_indicators(agent_id, time_win)

    assert isinstance(indicators, list)
    assert len(indicators) > 0


# Property 45: Cross-Pillar C2 Correlation
@pytest.mark.asyncio
@given(
    domain=st.sampled_from([
        "c2.attacker.com",
        "exfil-server.net",
        "10.0.0.42",
        "webhook.site",
    ]),
    tool_source=st.sampled_from(
        [EventSource.TOOL_CALL, EventSource.PIPELINE_EXECUTION]
    ),
    agent_id=st.text(min_size=1, max_size=15).filter(lambda s: bool(s.strip())),
)
@settings(max_examples=30)
async def test_property_45_cross_pillar_c2_correlation(
    domain: str, tool_source: EventSource, agent_id: str
):
    """Property 45: Correlated Kernel syscall (Pillar 1) + Tool Call (Pillar 4) events MUST generate cross-pillar correlation indicator."""
    detector = C2InfrastructureDetector()
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    # Pillar 1 event (Kernel Syscall)
    e1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=5),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="sys_connect",
        target=domain,
        metadata={"domain": domain},
        risk_score=0.6,
    )

    # Pillar 4 event (Tool Call / Pipeline Execution)
    e2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=10),
        source=tool_source,
        agent_id=agent_id,
        action="http_request",
        target=domain,
        metadata={},
        risk_score=0.6,
    )

    detector.record_event(e1)
    detector.record_event(e2)

    time_win = (base_time, base_time + timedelta(seconds=60))
    evidences = await detector.detect_c2_establishment(agent_id, time_win)

    assert len(evidences) >= 1
    ev = evidences[0]
    expected_indicator = (
        "Cross-pillar correlation between Pillar 1 network syscalls and tool calls"
    )
    assert expected_indicator in ev.persistence_indicators

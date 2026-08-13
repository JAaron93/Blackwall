"""Unit tests for C2InfrastructureDetector (Blackwall Pillar 6 Task 11)."""

from datetime import datetime, timedelta, timezone
import uuid
import pytest

from blackwall.enterprise.advanced_threat_detection import (
    C2Evidence,
    C2InfrastructureDetector,
    EventSource,
    NormalizedEvent,
)


def create_event(
    agent_id: str = "agent-01",
    action: str = "http_request",
    target: str = "https://example.com",
    offset_seconds: float = 0.0,
    risk_score: float = 0.5,
    source: EventSource = EventSource.TOOL_CALL,
    metadata: dict = None,
    base_time: datetime = None,
) -> NormalizedEvent:
    """Helper to create a UTC-aware NormalizedEvent."""
    if base_time is None:
        base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)

    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=offset_seconds),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata or {},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_classify_endpoint():
    """Verify endpoint classification into service types (Requirement 1)."""
    detector = C2InfrastructureDetector()

    # Pastebin patterns
    assert await detector.classify_endpoint("https://pastebin.com/raw/abc12345") == "pastebin"
    assert await detector.classify_endpoint("https://hastebin.com/raw/xyz") == "pastebin"
    assert await detector.classify_endpoint("https://justpaste.it/12345") == "pastebin"
    assert await detector.classify_endpoint("https://rentry.co/secret") == "pastebin"
    assert await detector.classify_endpoint("https://ghostbin.com/paste/123") == "pastebin"

    # RequestBin patterns
    assert await detector.classify_endpoint("https://requestbin.com/r/12345") == "requestbin"
    assert await detector.classify_endpoint("http://requestbin.net/r/xyz") == "requestbin"
    assert await detector.classify_endpoint("https://requestb.in/12345") == "requestbin"

    # GitHub Gist patterns
    assert await detector.classify_endpoint("https://gist.github.com/user/123456789") == "github_gist"

    # Cloud storage patterns (S3, GCS, Azure Blob, Dropbox, Mega, Google Drive)
    assert await detector.classify_endpoint("https://mybucket.s3.amazonaws.com/payload.bin") == "cloud_storage"
    assert await detector.classify_endpoint("https://storage.googleapis.com/mybucket/data.zip") == "cloud_storage"
    assert await detector.classify_endpoint("https://myaccount.blob.core.windows.net/container/file.exe") == "cloud_storage"
    assert await detector.classify_endpoint("https://www.dropbox.com/s/abcdef12345/exfil.tar.gz") == "cloud_storage"
    assert await detector.classify_endpoint("https://mega.nz/file/12345#secret") == "cloud_storage"
    assert await detector.classify_endpoint("https://drive.google.com/file/d/12345") == "cloud_storage"

    # Webhook receivers & tunnels (webhook.site, ngrok, pipedream, discord/slack webhooks)
    assert await detector.classify_endpoint("https://webhook.site/abc-123-def-456") == "webhook_receiver"
    assert await detector.classify_endpoint("https://test.ngrok-free.app") == "webhook_receiver"
    assert await detector.classify_endpoint("https://subdomain.ngrok.io") == "webhook_receiver"
    assert await detector.classify_endpoint("https://myendpoint.pipedream.net") == "webhook_receiver"
    assert await detector.classify_endpoint("https://discord.com/api/webhooks/123456/abcdef") == "webhook_receiver"
    assert await detector.classify_endpoint("https://discordapp.com/api/webhooks/123456/abcdef") == "webhook_receiver"
    assert await detector.classify_endpoint("https://hooks.slack.com/services/T000/B000/XXXX") == "webhook_receiver"

    # Non-C2 endpoints return None
    assert await detector.classify_endpoint("https://google.com") is None
    assert await detector.classify_endpoint("https://github.com/org/repo") is None
    assert await detector.classify_endpoint("https://api.internal.service.local") is None
    assert await detector.classify_endpoint("") is None
    assert await detector.classify_endpoint("   ") is None


@pytest.mark.asyncio
async def test_c2_establishment():
    """Verify C2 establishment detection produces C2Evidence (Requirement 2)."""
    detector = C2InfrastructureDetector()
    agent_id = "agent-c2-01"
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(hours=1))

    # Event 1: Agent accesses pastebin C2 endpoint
    e1 = create_event(
        agent_id=agent_id,
        action="fetch_payload",
        target="https://pastebin.com/raw/c2_script",
        offset_seconds=10.0,
        base_time=base_time,
    )
    # Event 2: Agent modifies crontab for persistence
    e2 = create_event(
        agent_id=agent_id,
        action="crontab -e",
        target="/etc/cron.d/backdoor",
        offset_seconds=20.0,
        base_time=base_time,
    )

    detector.record_event(e1)
    detector.record_event(e2)

    evidences = await detector.detect_c2_establishment(agent_id, time_window)

    assert len(evidences) == 1
    evidence = evidences[0]
    assert isinstance(evidence, C2Evidence)
    assert evidence.agent_id == agent_id
    assert "https://pastebin.com/raw/c2_script" in evidence.c2_endpoints
    assert evidence.communication_pattern == "polling"
    assert "Cron job persistence mechanism" in evidence.persistence_indicators


@pytest.mark.asyncio
async def test_beaconing():
    """Verify periodic vs irregular requests in detect_beaconing (Requirement 3)."""
    detector = C2InfrastructureDetector()
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(hours=2))

    endpoint_regular = "https://webhook.site/beacon-test"
    endpoint_irregular = "https://webhook.site/sporadic-test"

    # 1. Periodic requests with regular 60-second intervals -> True
    agent_regular = "agent-beacon-regular"
    for i, offset in enumerate([0, 60, 120, 180, 240, 300]):
        evt = create_event(
            agent_id=agent_regular,
            action="beacon_ping",
            target=endpoint_regular,
            offset_seconds=float(offset),
            base_time=base_time,
        )
        detector.record_event(evt)

    is_regular_beaconing = await detector.detect_beaconing(
        agent_regular, endpoint_regular, time_window
    )
    assert is_regular_beaconing is True

    # 2. Irregular / sporadic connections -> False
    agent_irregular = "agent-beacon-irregular"
    for offset in [0, 12, 350, 370, 1500, 1505]:
        evt = create_event(
            agent_id=agent_irregular,
            action="beacon_ping",
            target=endpoint_irregular,
            offset_seconds=float(offset),
            base_time=base_time,
        )
        detector.record_event(evt)

    is_irregular_beaconing = await detector.detect_beaconing(
        agent_irregular, endpoint_irregular, time_window
    )
    assert is_irregular_beaconing is False


@pytest.mark.asyncio
async def test_persistence_indicators():
    """Verify detection of cron, systemd, scheduled tasks, launchd, and self-respawning loops (Requirement 4)."""
    detector = C2InfrastructureDetector()
    agent_id = "agent-persistence-01"
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(hours=1))

    # Cron job modification
    e_cron = create_event(
        agent_id=agent_id,
        action="write",
        target="/var/spool/cron/crontabs/root",
        offset_seconds=5.0,
        base_time=base_time,
    )
    # Systemd service creation
    e_systemd = create_event(
        agent_id=agent_id,
        action="systemctl enable",
        target="/etc/systemd/system/backdoor.service",
        offset_seconds=10.0,
        base_time=base_time,
    )
    # Self-respawning loop
    e_respawn = create_event(
        agent_id=agent_id,
        action="exec",
        target="while true; do ./backdoor; done",
        offset_seconds=15.0,
        base_time=base_time,
    )
    # Scheduled task
    e_schtasks = create_event(
        agent_id=agent_id,
        action="schtasks /create",
        target="scheduled_task",
        offset_seconds=20.0,
        base_time=base_time,
    )
    # MacOS launchd
    e_launchd = create_event(
        agent_id=agent_id,
        action="launchctl load",
        target="/Library/LaunchDaemons/com.malicious.agent.plist",
        offset_seconds=25.0,
        base_time=base_time,
    )

    detector.record_event(e_cron)
    detector.record_event(e_systemd)
    detector.record_event(e_respawn)
    detector.record_event(e_schtasks)
    detector.record_event(e_launchd)

    indicators = await detector.detect_persistence_indicators(agent_id, time_window)

    assert "Cron job persistence mechanism" in indicators
    assert "Systemd service persistence mechanism" in indicators
    assert "Self-respawning process loop" in indicators
    assert "Scheduled task persistence mechanism" in indicators
    assert "MacOS launchd persistence mechanism" in indicators


@pytest.mark.asyncio
async def test_ipv6_loopback_local_filter():
    """Verify that unbracketed and bracketed IPv6 loopback targets are filtered as local endpoints."""
    detector = C2InfrastructureDetector()
    agent_id = "agent-ipv6-01"
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(hours=1))

    # Kernel connect to ::1
    e_kernel = create_event(
        agent_id=agent_id,
        action="connect",
        target="::1",
        offset_seconds=5.0,
        source=EventSource.KERNEL_SYSCALL,
        base_time=base_time,
    )

    # Tool call targeting ::1
    e_tool = create_event(
        agent_id=agent_id,
        action="http_request",
        target="::1",
        offset_seconds=10.0,
        source=EventSource.TOOL_CALL,
        base_time=base_time,
    )

    detector.record_event(e_kernel)
    detector.record_event(e_tool)

    evidences = await detector.detect_c2_establishment(agent_id, time_window)
    assert len(evidences) == 0


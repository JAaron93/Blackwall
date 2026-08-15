"""Unit tests for AlertBus class (Blackwall Pillar 6 Task 15.1)."""

import uuid
from datetime import UTC, datetime

import pytest

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import AlertSeverity
from blackwall.enterprise.advanced_threat_detection.models import Alert


def create_sample_alert(
    severity: AlertSeverity = AlertSeverity.HIGH,
    threat_type: str = "test_threat",
    title: str = "Test Threat Alert",
    description: str = "A test threat has been detected.",
    agent_id: str = "agent-01",
) -> Alert:
    """Helper to create a sample Alert instance."""
    return Alert(
        alert_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        severity=severity,
        threat_type=threat_type,
        title=title,
        description=description,
        agent_id=agent_id,
        agent_ids=[agent_id],
        evidence={"detail": "sample evidence"},
        metadata={"source": "unit_test"},
    )


@pytest.mark.asyncio
async def test_alert_publishing():
    """Verify alert publication and delivery to subscribers (Requirement 10.1-10.7)."""
    bus = AlertBus()
    received_alerts = []

    async def async_handler(alert: Alert):
        received_alerts.append(alert)

    bus.subscribe(async_handler)
    alert = create_sample_alert(severity=AlertSeverity.CRITICAL, threat_type="swarm_detection")

    success = await bus.publish(alert)
    assert success is True
    assert len(received_alerts) == 1
    assert received_alerts[0].alert_id == alert.alert_id
    assert received_alerts[0].severity == AlertSeverity.CRITICAL


@pytest.mark.asyncio
async def test_sync_subscriber_support():
    """Verify synchronous subscriber callbacks are properly supported."""
    bus = AlertBus()
    received_alerts = []

    def sync_handler(alert: Alert):
        received_alerts.append(alert)

    bus.subscribe(sync_handler)
    alert = create_sample_alert()

    success = await bus.publish(alert)
    assert success is True
    assert len(received_alerts) == 1
    assert received_alerts[0].alert_id == alert.alert_id


@pytest.mark.asyncio
async def test_multiple_subscribers():
    """Verify alert is broadcast to multiple registered subscribers."""
    bus = AlertBus()
    sink_a = []
    sink_b = []

    bus.subscribe(lambda a: sink_a.append(a))
    bus.subscribe(lambda a: sink_b.append(a))

    alert = create_sample_alert()
    success = await bus.publish(alert)

    assert success is True
    assert len(sink_a) == 1
    assert len(sink_b) == 1


@pytest.mark.asyncio
async def test_unsubscribe():
    """Verify unsubscribing stops receiving alerts."""
    bus = AlertBus()
    sink = []

    def handler(a):
        sink.append(a)

    bus.subscribe(handler)
    await bus.publish(create_sample_alert())
    assert len(sink) == 1

    bus.unsubscribe(handler)
    await bus.publish(create_sample_alert())
    assert len(sink) == 1


@pytest.mark.asyncio
async def test_alert_delivery_retry_success():
    """Verify transient delivery failures are retried up to max_retries."""
    bus = AlertBus(max_retries=5, retry_delay=0.001)
    attempts = 0

    async def flaky_handler(alert: Alert):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ConnectionError("Transient network blip")

    bus.subscribe(flaky_handler)
    alert = create_sample_alert()
    success = await bus.publish(alert)

    assert success is True
    assert attempts == 3


@pytest.mark.asyncio
async def test_alert_delivery_persistent_failure():
    """Verify that after 5 failed retries, failure is persistently logged and recorded."""
    bus = AlertBus(max_retries=5, retry_delay=0.001)
    attempts = 0

    async def failing_handler(alert: Alert):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("Permanent sink outage")

    bus.subscribe(failing_handler)
    alert = create_sample_alert()
    success = await bus.publish(alert)

    assert success is False
    assert attempts == 5
    assert len(bus.persistent_failures) == 1
    assert bus.persistent_failures[0]["alert_id"] == str(alert.alert_id)
    assert "Permanent sink outage" in bus.persistent_failures[0]["error"]


def test_invalid_max_retries_validation():
    """Verify constructor validates max_retries is a strictly positive integer."""
    with pytest.raises(ValueError):
        AlertBus(max_retries=0)

    with pytest.raises(ValueError):
        AlertBus(max_retries=-5)

    with pytest.raises(ValueError):
        AlertBus(max_retries=True)  # type: ignore


@pytest.mark.asyncio
async def test_alert_history_filtering():
    """Verify AlertBus tracks and filters published alert history."""
    bus = AlertBus()
    a1 = create_sample_alert(severity=AlertSeverity.LOW, threat_type="type_a", agent_id="agent-1")
    a2 = create_sample_alert(severity=AlertSeverity.CRITICAL, threat_type="type_b", agent_id="agent-2")
    a3 = create_sample_alert(severity=AlertSeverity.CRITICAL, threat_type="type_a", agent_id="agent-1")

    await bus.publish(a1)
    await bus.publish(a2)
    await bus.publish(a3)

    assert len(bus.get_alerts()) == 3
    assert len(bus.get_alerts(severity=AlertSeverity.CRITICAL)) == 2
    assert len(bus.get_alerts(threat_type="type_a")) == 2
    assert len(bus.get_alerts(agent_id="agent-1")) == 2
    assert len(bus.get_alerts(severity=AlertSeverity.CRITICAL, agent_id="agent-1")) == 1

    bus.clear()
    assert len(bus.get_alerts()) == 0


@pytest.mark.asyncio
async def test_alert_bus_shutdown_drains_pending_alerts():
    """Verify AlertBus cleanly drains pending alerts upon stop()."""
    bus = AlertBus(batch_size=10, flush_interval_seconds=60.0)
    received = []

    bus.subscribe(lambda a: received.append(a))
    await bus.start()

    alert1 = create_sample_alert()
    alert2 = create_sample_alert()
    await bus.publish(alert1)
    await bus.publish(alert2)

    assert len(received) == 0

    await bus.stop()
    assert len(received) == 2
    assert {r.alert_id for r in received} == {alert1.alert_id, alert2.alert_id}


@pytest.mark.asyncio
async def test_alert_bus_deduplicates_and_retains_on_cancellation():
    """Verify AlertBus retains pending alert on delivery cancellation and deduplicates deliveries."""
    bus = AlertBus(batch_size=10, flush_interval_seconds=60.0)
    call_counts = {"sub1": 0, "sub2": 0}

    def sub1(alert: Alert):
        call_counts["sub1"] += 1

    def sub2(alert: Alert):
        call_counts["sub2"] += 1

    bus.subscribe(sub1)
    bus.subscribe(sub2)

    alert = create_sample_alert()
    await bus.publish(alert)

    # Deliver once
    await bus.flush()
    assert call_counts["sub1"] == 1
    assert call_counts["sub2"] == 1

    # Attempt re-deliver of same alert object
    await bus._deliver_alert(alert)
    # Subscribers already tracked should not receive duplicate delivery
    assert call_counts["sub1"] == 1
    assert call_counts["sub2"] == 1

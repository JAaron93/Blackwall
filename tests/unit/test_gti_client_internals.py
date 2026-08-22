"""Unit tests for GTI Client internals — GTIMCPClient and GTIQueryBudgetTracker.

Tests cover private methods: _calculate_entropy, _parse_vt_response, _is_private_ip,
_handle_failure, _ensure_task_started, _replenish_loop;
and public methods: record_cache_hit, try_acquire, is_degraded, get_metrics.
"""

import pytest
import asyncio
import math
import time
from unittest.mock import AsyncMock, MagicMock, patch

from blackwall.mcp.gti_client import (
    BudgetMetrics,
    GTIBudgetExhaustedError,
    GTIClient,
    GTIDegradedError,
    GTIMCPClient,
    GTIQueryBudgetTracker,
)
from blackwall.models import GTIResponse, IndicatorType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_gti_client() -> GTIMCPClient:
    """Create a GTIMCPClient with mocked repo and a test API key."""
    return GTIMCPClient(repo=MagicMock(), api_key="test_key")


# ---------------------------------------------------------------------------
# Section 1: GTIQueryBudgetTracker tests
# ---------------------------------------------------------------------------


class TestGTIQueryBudgetTrackerInit:
    """Initialization and defaults."""

    async def test_budget_tracker_init_defaults(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            assert tracker.capacity == 4
            assert tracker.tokens == 4.0
            assert tracker.queries_attempted == 0
            assert tracker.queries_executed == 0
            assert tracker.queries_deferred == 0
            assert tracker.cache_hits == 0
            assert tracker.queriesAttempted == 0
            assert tracker.queriesExecuted == 0
            assert tracker.queriesDeferred == 0
            assert tracker.cacheHits == 0
            assert tracker.budgetExhaustionCount == 0
        finally:
            tracker.close()

    async def test_budget_tracker_init_custom(self):
        tracker = GTIQueryBudgetTracker(capacity=10, replenishment_interval=30.0)
        try:
            assert tracker.capacity == 10
            assert tracker.tokens == 10.0
            assert tracker.replenishment_interval == 30.0
        finally:
            tracker.close()


class TestGTIQueryBudgetTrackerAcquire:
    """Token acquisition behavior."""

    async def test_try_acquire_returns_true_when_tokens_available(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            result = await tracker.try_acquire()
            assert result is True
        finally:
            tracker.close()

    async def test_try_acquire_returns_false_when_exhausted(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            results = []
            for _ in range(5):
                results.append(await tracker.try_acquire())
            # First 4 should succeed, 5th should fail
            assert results[0] is True
            assert results[1] is True
            assert results[2] is True
            assert results[3] is True
            assert results[4] is False
        finally:
            tracker.close()

    async def test_try_acquire_decrements_tokens(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            await tracker.try_acquire()
            available = await tracker.get_available_tokens()
            assert available == 3
        finally:
            tracker.close()

    async def test_try_acquire_increments_metrics(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            await tracker.try_acquire()
            assert tracker.queries_attempted == 1
            assert tracker.queries_executed == 1
            assert tracker.queriesAttempted == 1
            assert tracker.queriesExecuted == 1
        finally:
            tracker.close()

    async def test_try_acquire_deferred_on_exhaustion(self):
        tracker = GTIQueryBudgetTracker(capacity=1, replenishment_interval=15.0)
        try:
            await tracker.try_acquire()  # exhausts the single token
            await tracker.try_acquire()  # should be deferred
            assert tracker.queries_deferred == 1
            assert tracker.queriesDeferred == 1
            assert tracker.budgetExhaustionCount == 1
        finally:
            tracker.close()


class TestGTIQueryBudgetTrackerCacheAndTokens:
    """Cache hit recording and token queries."""

    async def test_record_cache_hit_increments_metrics(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            await tracker.record_cache_hit()
            assert tracker.cache_hits == 1
            assert tracker.cacheHits == 1
            assert tracker.queries_attempted == 1
            assert tracker.queriesAttempted == 1
        finally:
            tracker.close()

    async def test_get_available_tokens_returns_int(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            result = await tracker.get_available_tokens()
            assert isinstance(result, int)
            assert result == 4
        finally:
            tracker.close()


class TestGTIQueryBudgetTrackerMetrics:
    """Metrics retrieval."""

    async def test_get_metrics_returns_budget_metrics(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            metrics = await tracker.get_metrics()
            assert isinstance(metrics, BudgetMetrics)
            assert metrics.queries_attempted == 0
            assert metrics.queries_executed == 0
            assert metrics.queries_deferred == 0
            assert metrics.cache_hits == 0
            assert metrics.avgTokenReplenishmentInterval == 15.0
        finally:
            tracker.close()

    async def test_get_metrics_cache_hit_rate(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            # Record 2 cache hits and 2 acquires = 4 total attempts, 2 cache hits
            await tracker.record_cache_hit()
            await tracker.record_cache_hit()
            await tracker.try_acquire()
            await tracker.try_acquire()
            metrics = await tracker.get_metrics()
            # cache_hits = 2, queries_attempted = 4
            assert metrics.cache_hit_rate == pytest.approx(0.5)
        finally:
            tracker.close()


class TestGTIQueryBudgetTrackerReset:
    """Reset behavior."""

    async def test_reset_restores_tokens(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            # Drain tokens
            for _ in range(4):
                await tracker.try_acquire()
            available = await tracker.get_available_tokens()
            assert available == 0

            # Reset
            await tracker.reset()
            available = await tracker.get_available_tokens()
            assert available == 4
            assert tracker.queries_attempted == 0
            assert tracker.queries_executed == 0
            assert tracker.queries_deferred == 0
            assert tracker.cache_hits == 0
            assert tracker.budgetExhaustionCount == 0
        finally:
            tracker.close()


class TestGTIQueryBudgetTrackerLifecycle:
    """Task lifecycle management."""

    async def test_close_cancels_task(self):
        # Run inside async context so _ensure_task_started can create a task
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        assert tracker._replenish_task is not None
        tracker.close()
        assert tracker._replenish_task is None

    async def test_ensure_task_started_idempotent(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            first_task = tracker._replenish_task
            tracker._ensure_task_started()
            second_task = tracker._replenish_task
            assert first_task is second_task
        finally:
            tracker.close()


class TestGTIQueryBudgetTrackerReplenish:
    """Replenish loop behavior."""

    async def test_replenish_loop_increments_tokens(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            # Drain one token
            await tracker.try_acquire()
            assert await tracker.get_available_tokens() == 3

            # Simulate replenishment by calling the internal logic directly
            with patch("asyncio.sleep", new_callable=AsyncMock, side_effect=[None, asyncio.CancelledError()]):
                # Manually set tokens below capacity and run one iteration
                async with tracker.lock:
                    tracker.tokens = 3.0
                # Run replenish loop - it will sleep once (mocked), add token, sleep again (CancelledError)
                try:
                    await tracker._replenish_loop()
                except asyncio.CancelledError:
                    pass
                assert tracker.tokens == 4.0
        finally:
            tracker.close()

    async def test_replenish_loop_does_not_exceed_capacity(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            # Tokens are already at capacity
            with patch("asyncio.sleep", new_callable=AsyncMock, side_effect=[None, asyncio.CancelledError()]):
                try:
                    await tracker._replenish_loop()
                except asyncio.CancelledError:
                    pass
                # Should not exceed capacity
                assert tracker.tokens <= tracker.capacity
        finally:
            tracker.close()

    async def test_replenish_loop_cancelled_gracefully(self):
        tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
        try:
            with patch("asyncio.sleep", new_callable=AsyncMock, side_effect=asyncio.CancelledError()):
                # Should not raise - CancelledError is handled internally
                await tracker._replenish_loop()
        finally:
            tracker.close()


# ---------------------------------------------------------------------------
# Section 2: GTIMCPClient._calculate_entropy tests
# ---------------------------------------------------------------------------


class TestCalculateEntropy:
    """Entropy calculation for strings."""

    def test_calculate_entropy_empty_string(self):
        client = make_gti_client()
        assert client._calculate_entropy("") == 0.0

    def test_calculate_entropy_all_same_chars(self):
        client = make_gti_client()
        assert client._calculate_entropy("aaaa") == 0.0

    def test_calculate_entropy_uuid_style(self):
        client = make_gti_client()
        # UUID-like string with high entropy
        uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        entropy = client._calculate_entropy(uuid_str)
        assert entropy > 3.0

    def test_calculate_entropy_two_chars(self):
        client = make_gti_client()
        # "aabb" -> 2 chars each appearing 2/4 times
        # entropy = -2*(0.5 * log2(0.5)) = -2*(-0.5) = 1.0
        entropy = client._calculate_entropy("aabb")
        assert entropy == pytest.approx(1.0)

    def test_calculate_entropy_single_char(self):
        client = make_gti_client()
        # Single character "x" -> only one unique char, p=1.0, -1.0*log2(1.0)=0.0
        assert client._calculate_entropy("x") == 0.0


# ---------------------------------------------------------------------------
# Section 3: GTIMCPClient._is_private_ip tests
# ---------------------------------------------------------------------------


class TestIsPrivateIp:
    """Private IP address detection."""

    def test_is_private_ip_localhost(self):
        client = make_gti_client()
        assert client._is_private_ip("127.0.0.1") is True

    def test_is_private_ip_localhost_str(self):
        client = make_gti_client()
        assert client._is_private_ip("localhost") is True

    def test_is_private_ip_10_range(self):
        client = make_gti_client()
        assert client._is_private_ip("10.0.0.1") is True

    def test_is_private_ip_10_range_boundary(self):
        client = make_gti_client()
        assert client._is_private_ip("10.255.255.255") is True

    def test_is_private_ip_192_168_range(self):
        client = make_gti_client()
        assert client._is_private_ip("192.168.0.1") is True

    def test_is_private_ip_172_16(self):
        client = make_gti_client()
        assert client._is_private_ip("172.16.0.1") is True

    def test_is_private_ip_172_31(self):
        client = make_gti_client()
        assert client._is_private_ip("172.31.255.255") is True

    def test_is_private_ip_172_32_public(self):
        client = make_gti_client()
        assert client._is_private_ip("172.32.0.1") is False

    def test_is_private_ip_172_15_public(self):
        client = make_gti_client()
        assert client._is_private_ip("172.15.0.1") is False

    def test_is_private_ip_public_google_dns(self):
        client = make_gti_client()
        assert client._is_private_ip("8.8.8.8") is False

    def test_is_private_ip_public_cloudflare(self):
        client = make_gti_client()
        assert client._is_private_ip("1.1.1.1") is False

    def test_is_private_ip_public_non_private_10x(self):
        client = make_gti_client()
        # "100.0.0.1" starts with "1" but not "10."
        assert client._is_private_ip("100.0.0.1") is False


# ---------------------------------------------------------------------------
# Section 4: GTIMCPClient._parse_vt_response tests
# ---------------------------------------------------------------------------


class TestParseVtResponse:
    """VirusTotal response parsing."""

    def test_parse_vt_response_clean_indicator(self):
        client = make_gti_client()
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 50,
                        "undetected": 20,
                    },
                    "last_analysis_results": {},
                    "tags": [],
                }
            }
        }
        result = client._parse_vt_response("8.8.8.8", vt_data)
        assert result["indicator"] == "8.8.8.8"
        assert result["is_malicious"] is False
        assert result["detection_rate"] == 0.0
        assert result["threat_categories"] == []
        assert result["related_campaigns"] == []

    def test_parse_vt_response_malicious_indicator(self):
        client = make_gti_client()
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,
                        "suspicious": 0,
                        "harmless": 80,
                        "undetected": 10,
                    },
                    "last_analysis_results": {},
                    "tags": [],
                }
            }
        }
        result = client._parse_vt_response("evil.com", vt_data)
        assert result["is_malicious"] is True
        assert result["detection_rate"] == pytest.approx(10.0)

    def test_parse_vt_response_empty_data(self):
        client = make_gti_client()
        vt_data = {}
        result = client._parse_vt_response("unknown.com", vt_data)
        assert result["indicator"] == "unknown.com"
        assert result["is_malicious"] is False
        assert result["detection_rate"] == 0.0
        assert result["confidence"] == 0.0

    def test_parse_vt_response_missing_attributes(self):
        client = make_gti_client()
        vt_data = {"data": {}}
        result = client._parse_vt_response("test.com", vt_data)
        assert result["indicator"] == "test.com"
        assert result["is_malicious"] is False
        assert result["detection_rate"] == 0.0

    def test_parse_vt_response_with_tags_campaign(self):
        client = make_gti_client()
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 0,
                        "harmless": 45,
                        "undetected": 0,
                    },
                    "last_analysis_results": {},
                    "tags": ["c2-botnet", "dropper", "campaign-apt29"],
                }
            }
        }
        result = client._parse_vt_response("bad.ip", vt_data)
        assert "c2-botnet" in result["related_campaigns"]
        assert "campaign-apt29" in result["related_campaigns"]
        # "dropper" has neither "campaign" nor starts with "c2-"
        assert "dropper" not in result["related_campaigns"]

    def test_parse_vt_response_with_last_analysis_date(self):
        client = make_gti_client()
        # Unix timestamp: 1700000000 -> 2023-11-14T22:13:20+00:00
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 10,
                        "undetected": 0,
                    },
                    "last_analysis_results": {},
                    "tags": [],
                    "last_analysis_date": 1700000000,
                }
            }
        }
        result = client._parse_vt_response("example.com", vt_data)
        assert result["last_analysis_date"] is not None
        assert "2023-11-14" in result["last_analysis_date"]

    def test_parse_vt_response_threat_categories(self):
        client = make_gti_client()
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 46,
                        "undetected": 0,
                    },
                    "last_analysis_results": {
                        "engine1": {"category": "malicious", "result": "Trojan.GenericKD"},
                        "engine2": {"category": "malicious", "result": "W32/Malware"},
                        "engine3": {"category": "suspicious", "result": "PUP.Optional"},
                        "engine4": {"category": "undetected", "result": None},
                    },
                    "tags": [],
                }
            }
        }
        result = client._parse_vt_response("malware.exe", vt_data)
        # Categories should be lowercased and sorted
        assert "trojan.generickd" in result["threat_categories"]
        assert "w32/malware" in result["threat_categories"]
        assert "pup.optional" in result["threat_categories"]

    def test_parse_vt_response_confidence_calculation(self):
        client = make_gti_client()
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 25,
                        "suspicious": 0,
                        "harmless": 50,
                        "undetected": 25,
                    },
                    "last_analysis_results": {},
                    "tags": [],
                }
            }
        }
        result = client._parse_vt_response("test.hash", vt_data)
        # confidence = malicious / total = 25 / 100 = 0.25
        assert result["confidence"] == pytest.approx(0.25)


# ---------------------------------------------------------------------------
# Section 5: GTIMCPClient._handle_failure tests
# ---------------------------------------------------------------------------


class TestHandleFailure:
    """Circuit breaker failure handling."""

    def test_handle_failure_increments_consecutive_failures(self):
        client = make_gti_client()
        assert client.consecutive_failures == 0
        client._handle_failure()
        assert client.consecutive_failures == 1

    def test_handle_failure_transitions_to_open_at_5(self):
        client = make_gti_client()
        assert client.state == "CLOSED"
        for _ in range(5):
            client._handle_failure()
        assert client.state == "OPEN"
        assert client.consecutive_failures == 5

    def test_handle_failure_in_half_open_resets_to_open(self):
        client = make_gti_client()
        client.state = "HALF-OPEN"
        client._handle_failure()
        assert client.state == "OPEN"
        assert client.successful_retries == 0

    def test_handle_failure_records_last_state_change(self):
        client = make_gti_client()
        client.state = "HALF-OPEN"
        before = time.time()
        client._handle_failure()
        after = time.time()
        assert before <= client.last_state_change <= after


# ---------------------------------------------------------------------------
# Section 6: GTIMCPClient.is_degraded tests
# ---------------------------------------------------------------------------


class TestIsDegraded:
    """Circuit breaker degraded state checks."""

    def test_is_degraded_closed_state(self):
        client = make_gti_client()
        client.state = "CLOSED"
        assert client.is_degraded() is False

    def test_is_degraded_open_during_cooldown(self):
        client = make_gti_client()
        client.state = "OPEN"
        client.last_state_change = time.time()  # Just now
        client.cooldown = 60.0
        assert client.is_degraded() is True

    def test_is_degraded_open_after_cooldown(self):
        client = make_gti_client()
        client.state = "OPEN"
        client.cooldown = 60.0
        # Set last_state_change to well in the past (beyond cooldown)
        with patch("blackwall.mcp.gti_client.time.time", return_value=time.time() + 120):
            result = client.is_degraded()
        assert result is False
        assert client.state == "HALF-OPEN"


# ---------------------------------------------------------------------------
# Section 7: GTIClient basic stub tests
# ---------------------------------------------------------------------------


class TestGTIClientStubs:
    """GTIClient stub methods return GTIResponse with is_malicious=False."""

    async def test_gti_client_lookup_ip(self):
        client = GTIClient(api_key="test")
        result = await client.lookup_ip("192.168.1.1")
        assert isinstance(result, GTIResponse)
        assert result.indicator == "192.168.1.1"
        assert result.is_malicious is False

    async def test_gti_client_lookup_domain(self):
        client = GTIClient(api_key="test")
        result = await client.lookup_domain("example.com")
        assert isinstance(result, GTIResponse)
        assert result.indicator == "example.com"
        assert result.is_malicious is False

    async def test_gti_client_lookup_url(self):
        client = GTIClient(api_key="test")
        result = await client.lookup_url("https://example.com/path")
        assert isinstance(result, GTIResponse)
        assert result.indicator == "https://example.com/path"
        assert result.is_malicious is False

    async def test_gti_client_lookup_file_hash(self):
        client = GTIClient(api_key="test")
        result = await client.lookup_file_hash("abc123def456")
        assert isinstance(result, GTIResponse)
        assert result.indicator == "abc123def456"
        assert result.is_malicious is False

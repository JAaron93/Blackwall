import asyncio
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from blackwall.mcp.gti_client import GTIMCPClient, GTIDegradedError
from blackwall.models import IndicatorType, GTIResponse
from blackwall.db.repository import SQLiteThreatRepository


@pytest.fixture
def temp_db_path(tmp_path):
    return str(tmp_path / "test_blackwall.db")


@pytest.fixture
async def repo(temp_db_path):
    repo = SQLiteThreatRepository(temp_db_path)
    await repo.initialize()
    yield repo
    await repo.close()


@pytest.fixture
def client(repo):
    return GTIMCPClient(repo=repo, api_key="test_api_key")


@pytest.mark.asyncio
async def test_ioc_query_malicious_ip(client):
    # Mock _execute_api_query to return a malicious IP response
    mock_response = {
        "indicator": "192.168.1.1",
        "is_malicious": True,
        "threat_categories": ["malware", "botnet"],
        "detection_rate": 20.0,
        "last_analysis_date": "2026-07-05T12:00:00Z",
        "related_campaigns": ["campaign_alpha"],
        "confidence": 0.2
    }

    with patch.object(client, "_execute_api_query", new_callable=AsyncMock) as mock_query:
        mock_query.return_value = mock_response

        response = await client.queryIOC("192.168.1.1", IndicatorType.IP_ADDRESS)

        assert isinstance(response, GTIResponse)
        assert response.is_malicious is True
        assert "malware" in response.threat_categories
        assert response.detection_rate == 20.0
        assert response.confidence == 0.2
        assert response.indicator == "192.168.1.1"
        mock_query.assert_called_once_with("192.168.1.1", IndicatorType.IP_ADDRESS)


@pytest.mark.asyncio
async def test_caching_and_ttl(client, repo):
    mock_response = {
        "indicator": "example.com",
        "is_malicious": False,
        "threat_categories": [],
        "detection_rate": 0.0,
        "last_analysis_date": "2026-07-05T12:00:00Z",
        "related_campaigns": [],
        "confidence": 0.0
    }

    with patch.object(client, "_execute_api_query", new_callable=AsyncMock) as mock_query:
        mock_query.return_value = mock_response

        # First query should call API
        resp1 = await client.queryIOC("example.com", IndicatorType.DOMAIN)
        assert mock_query.call_count == 1

        # Second query should hit cache (no API call)
        resp2 = await client.queryIOC("example.com", IndicatorType.DOMAIN)
        assert mock_query.call_count == 1
        assert resp1 == resp2

        # Now mock time to be 24h + 1s later
        with patch("time.time", return_value=time.time() + 86401):
            # Third query should miss cache and call API
            resp3 = await client.queryIOC("example.com", IndicatorType.DOMAIN)
            assert mock_query.call_count == 2


@pytest.mark.asyncio
async def test_timeout_triggers_failure(client):
    with patch.object(client, "_execute_api_query", new_callable=AsyncMock) as mock_query:
        # Mock wait_for timeout by raising TimeoutError
        mock_query.side_effect = asyncio.TimeoutError()

        with pytest.raises(asyncio.TimeoutError):
            await client.queryIOC("1.1.1.1", IndicatorType.IP_ADDRESS)

        assert client.consecutive_failures == 1


@pytest.mark.asyncio
async def test_circuit_breaker_degraded_mode(client):
    with patch.object(client, "_execute_api_query", new_callable=AsyncMock) as mock_query:
        mock_query.side_effect = Exception("API Error")

        # Fail 5 times
        for _ in range(5):
            with pytest.raises(Exception):
                await client.queryIOC("1.1.1.1", IndicatorType.IP_ADDRESS)

        assert client.state == "OPEN"
        assert client.consecutive_failures == 5

        # 6th call should raise GTIDegradedError without calling the API
        mock_query.reset_mock()
        with pytest.raises(GTIDegradedError):
            await client.queryIOC("1.1.1.1", IndicatorType.IP_ADDRESS)

        mock_query.assert_not_called()


@pytest.mark.asyncio
async def test_circuit_breaker_cooldown_and_restore(client):
    with patch.object(client, "_execute_api_query", new_callable=AsyncMock) as mock_query:
        mock_query.side_effect = Exception("API Error")

        # Fail 5 times to trigger OPEN state
        for _ in range(5):
            with pytest.raises(Exception):
                await client.queryIOC("1.1.1.1", IndicatorType.IP_ADDRESS)

        assert client.state == "OPEN"

        # Cooldown has NOT elapsed yet
        with pytest.raises(GTIDegradedError):
            await client.queryIOC("1.1.1.1", IndicatorType.IP_ADDRESS)

        # Simulate cooldown elapsed (61 seconds)
        mock_query.side_effect = None
        mock_query.return_value = {
            "indicator": "1.1.1.1",
            "is_malicious": False,
            "threat_categories": [],
            "detection_rate": 0.0,
            "last_analysis_date": None,
            "related_campaigns": [],
            "confidence": 0.0
        }

        with patch("time.time", return_value=time.time() + 61):
            # This call should transition to HALF-OPEN and execute the query
            await client.queryIOC("1.1.1.1", IndicatorType.IP_ADDRESS)
            assert client.state == "HALF-OPEN"
            assert client.successful_retries == 1

            # Need 2 more successful calls to return to CLOSED
            await client.queryIOC("2.2.2.2", IndicatorType.IP_ADDRESS)
            assert client.state == "HALF-OPEN"
            assert client.successful_retries == 2

            await client.queryIOC("3.3.3.3", IndicatorType.IP_ADDRESS)
            assert client.state == "CLOSED"
            assert client.successful_retries == 0


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_failure_resets(client):
    with patch.object(client, "_execute_api_query", new_callable=AsyncMock) as mock_query:
        mock_query.side_effect = Exception("API Error")

        # Fail 5 times to trigger OPEN state
        for _ in range(5):
            with pytest.raises(Exception):
                await client.queryIOC("1.1.1.1", IndicatorType.IP_ADDRESS)

        # Simulate cooldown elapsed (61 seconds), then trigger success, then failure
        mock_query.side_effect = None
        mock_query.return_value = {
            "indicator": "1.1.1.1",
            "is_malicious": False,
            "threat_categories": [],
            "detection_rate": 0.0,
            "last_analysis_date": None,
            "related_campaigns": [],
            "confidence": 0.0
        }

        with patch("time.time", return_value=time.time() + 61):
            # 1st call successful
            await client.queryIOC("1.1.1.1", IndicatorType.IP_ADDRESS)
            assert client.state == "HALF-OPEN"
            assert client.successful_retries == 1

            # 2nd call fails
            mock_query.side_effect = Exception("Second Failure")
            with pytest.raises(Exception):
                await client.queryIOC("2.2.2.2", IndicatorType.IP_ADDRESS)

            # Should immediately transition back to OPEN (degraded)
            assert client.state == "OPEN"
            assert client.successful_retries == 0


@pytest.mark.asyncio
async def test_threat_score_penalty_simulation(client):
    # Test threat score penalty of 0.3 applied in degraded mode.
    with patch.object(client, "_execute_api_query", new_callable=AsyncMock) as mock_query:
        mock_query.side_effect = Exception("API Error")
        for _ in range(5):
            with pytest.raises(Exception):
                await client.queryIOC("1.1.1.1", IndicatorType.IP_ADDRESS)

        # Now in degraded mode
        assert client.is_degraded() is True

        # Simulation of HybridPolicyServer penalty application
        threat_score = 0.0
        gti_penalty = 0.0
        try:
            await client.queryIOC("1.1.1.1", IndicatorType.IP_ADDRESS)
        except GTIDegradedError:
            gti_penalty = 0.3

        threat_score += gti_penalty
        assert threat_score == 0.3


@pytest.mark.asyncio
async def test_vt_response_parsing(client):
    # Test VT JSON parsing logic
    raw_vt_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 1,
                    "harmless": 20,
                    "undetected": 74
                },
                "last_analysis_results": {
                    "EngineA": {"category": "malicious", "result": "Malware_Name_1"},
                    "EngineB": {"category": "suspicious", "result": "Trojan.Generic"},
                    "EngineC": {"category": "harmless", "result": "clean"}
                },
                "tags": ["campaign:apt28", "c2-server", "some-other-tag"],
                "last_analysis_date": 1782302400  # Unix timestamp
            }
        }
    }

    parsed = client._parse_vt_response("8.8.8.8", raw_vt_data)

    assert parsed["indicator"] == "8.8.8.8"
    assert parsed["is_malicious"] is True
    assert parsed["detection_rate"] == 6.0  # 6 / 100 * 100
    assert "malware_name_1" in parsed["threat_categories"]
    assert "trojan.generic" in parsed["threat_categories"]
    assert "campaign:apt28" in parsed["related_campaigns"]
    assert parsed["confidence"] == 0.05  # 5 / 100
    assert parsed["last_analysis_date"] is not None


@pytest.mark.asyncio
async def test_rate_limit_backoff_and_retry(client):
    # Test that HTTP 429 response triggers backoff and retry
    mock_resp_429 = MagicMock()
    mock_resp_429.status = 429
    mock_resp_429.headers = {}

    mock_resp_200 = MagicMock()
    mock_resp_200.status = 200
    mock_resp_200.json = AsyncMock(return_value={
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 0}
            }
        }
    })

    with patch("aiohttp.ClientSession.get") as mock_get, patch("asyncio.sleep", AsyncMock()) as mock_sleep:
        mock_ctx_429 = MagicMock()
        mock_ctx_429.__aenter__ = AsyncMock(return_value=mock_resp_429)
        mock_ctx_429.__aexit__ = AsyncMock(return_value=None)

        mock_ctx_200 = MagicMock()
        mock_ctx_200.__aenter__ = AsyncMock(return_value=mock_resp_200)
        mock_ctx_200.__aexit__ = AsyncMock(return_value=None)

        mock_get.side_effect = [mock_ctx_429, mock_ctx_429, mock_ctx_200]

        parsed = await client._execute_api_query("8.8.8.8", IndicatorType.IP_ADDRESS)

        assert parsed["is_malicious"] is False
        assert mock_get.call_count == 3
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(0.1)
        mock_sleep.assert_any_call(0.2)

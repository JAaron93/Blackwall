from __future__ import annotations

from unittest.mock import AsyncMock, patch
import pytest

from blackwall.threat_intel.abuseipdb import (
    AbuseIPDBLookupError,
    AbuseIPDBProvider,
)
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelProvider,
)


@pytest.mark.asyncio
async def test_abuseipdb_initialization() -> None:
    provider = AbuseIPDBProvider(api_key="test-abuseipdb-key")
    assert provider.name == "abuseipdb"
    assert ThreatIndicatorType.IPV4 in provider.supported_indicators
    assert ThreatIndicatorType.IPV6 in provider.supported_indicators
    assert ThreatIndicatorType.DOMAIN not in provider.supported_indicators
    assert ThreatIndicatorType.URL not in provider.supported_indicators
    assert ThreatIndicatorType.FILE_HASH not in provider.supported_indicators
    assert provider.get_remaining_budget() > 0
    assert await provider.is_healthy() is True
    assert isinstance(provider, ThreatIntelProvider)


@pytest.mark.asyncio
async def test_abuseipdb_rejects_non_ip_indicators() -> None:
    provider = AbuseIPDBProvider(api_key="test-abuseipdb-key")

    with patch.object(provider, "_execute_http_get", new_callable=AsyncMock) as mock_get:
        # DOMAIN lookup must raise ValueError without making network request
        with pytest.raises(ValueError, match="only supports IP indicators"):
            await provider.lookup("example.com", ThreatIndicatorType.DOMAIN)

        # URL lookup must raise ValueError
        with pytest.raises(ValueError, match="only supports IP indicators"):
            await provider.lookup("http://example.com/malware", ThreatIndicatorType.URL)

        # FILE_HASH lookup must raise ValueError
        with pytest.raises(ValueError, match="only supports IP indicators"):
            await provider.lookup(
                "44d88612fea8a8f36de82e1278abb02f", ThreatIndicatorType.FILE_HASH
            )

        mock_get.assert_not_called()


@pytest.mark.asyncio
async def test_abuseipdb_lookup_ipv4_benign() -> None:
    provider = AbuseIPDBProvider(api_key="test-abuseipdb-key")

    mock_response = {
        "data": {
            "ipAddress": "8.8.8.8",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": True,
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "usageType": "DNS",
            "isp": "Google LLC",
            "domain": "google.com",
            "hostnames": ["dns.google"],
            "totalReports": 0,
            "numDistinctUsers": 0,
            "lastReportedAt": None,
            "reports": [],
        }
    }

    with patch.object(provider, "_execute_http_get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        resp = await provider.lookup("8.8.8.8", ThreatIndicatorType.IPV4)
        assert resp.indicator == "8.8.8.8"
        assert resp.indicator_type == ThreatIndicatorType.IPV4
        assert resp.is_malicious is False
        assert resp.risk_score == 0.0
        assert resp.detection_count == 0
        assert resp.provider_name == "abuseipdb"
        assert "https://www.abuseipdb.com/check/8.8.8.8" in resp.references


@pytest.mark.asyncio
async def test_abuseipdb_lookup_ipv4_malicious() -> None:
    provider = AbuseIPDBProvider(api_key="test-abuseipdb-key")

    mock_response = {
        "data": {
            "ipAddress": "198.51.100.1",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 85,
            "countryCode": "CN",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Bad Hosting Inc",
            "domain": "badhost.net",
            "hostnames": ["c2.badhost.net"],
            "totalReports": 42,
            "numDistinctUsers": 15,
            "lastReportedAt": "2026-09-16T12:00:00+00:00",
            "reports": [
                {
                    "reportedAt": "2026-09-16T12:00:00+00:00",
                    "comment": "SSH brute force attempts and C2 beaconing",
                    "categories": [18, 22],
                    "reporterId": 101,
                    "reporterCountryCode": "US",
                }
            ],
        }
    }

    with patch.object(provider, "_execute_http_get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        resp = await provider.lookup("198.51.100.1", ThreatIndicatorType.IPV4)
        assert resp.indicator == "198.51.100.1"
        assert resp.indicator_type == ThreatIndicatorType.IPV4
        assert resp.is_malicious is True
        assert resp.risk_score == 0.85
        assert resp.detection_count == 42
        assert resp.total_engines == 15
        assert resp.provider_name == "abuseipdb"
        assert "Data Center/Web Hosting/Transit" in resp.threat_categories or len(resp.threat_categories) > 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "confidence,expected_malicious,expected_risk",
    [
        (0, False, 0.0),
        (24, False, 0.24),
        (25, True, 0.25),
        (50, True, 0.5),
        (100, True, 1.0),
    ],
)
async def test_abuseipdb_confidence_threshold_mapping(
    confidence: int, expected_malicious: bool, expected_risk: float
) -> None:
    provider = AbuseIPDBProvider(api_key="test-abuseipdb-key")

    mock_response = {
        "data": {
            "ipAddress": "198.51.100.2",
            "abuseConfidenceScore": confidence,
            "totalReports": 5 if confidence > 0 else 0,
            "numDistinctUsers": 2 if confidence > 0 else 0,
        }
    }

    with patch.object(provider, "_execute_http_get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        resp = await provider.lookup("198.51.100.2", ThreatIndicatorType.IPV4)
        assert resp.is_malicious is expected_malicious
        assert resp.risk_score == expected_risk


@pytest.mark.asyncio
async def test_abuseipdb_missing_api_key() -> None:
    with patch.dict("os.environ", {}, clear=True), patch("os.path.exists", return_value=False):
        provider = AbuseIPDBProvider(api_key=None)
        assert provider.api_key == ""
        assert provider.get_remaining_budget() == 0
        assert await provider.is_healthy() is False

        with pytest.raises(AbuseIPDBLookupError, match="No AbuseIPDB API key configured"):
            await provider.lookup("1.1.1.1", ThreatIndicatorType.IPV4)


@pytest.mark.asyncio
async def test_abuseipdb_rate_limit_error() -> None:
    provider = AbuseIPDBProvider(api_key="test-key")

    with patch.object(provider, "_execute_http_get", side_effect=ConnectionError("HTTP 429 Too Many Requests")):
        with pytest.raises(AbuseIPDBLookupError):
            await provider.lookup("1.1.1.1", ThreatIndicatorType.IPV4)


@pytest.mark.asyncio
async def test_abuseipdb_lookup_ipv6() -> None:
    provider = AbuseIPDBProvider(api_key="test-key")

    mock_response = {
        "data": {
            "ipAddress": "2001:db8::1",
            "isPublic": True,
            "ipVersion": 6,
            "isWhitelisted": False,
            "abuseConfidenceScore": 50,
            "totalReports": 3,
            "numDistinctUsers": 2,
            "reports": [],
        }
    }

    with patch.object(provider, "_execute_http_get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        resp = await provider.lookup("2001:db8::1", ThreatIndicatorType.IPV6)
        assert resp.indicator == "2001:db8::1"
        assert resp.indicator_type == ThreatIndicatorType.IPV6
        assert resp.is_malicious is True
        assert resp.risk_score == 0.5


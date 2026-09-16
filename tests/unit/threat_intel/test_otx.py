from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blackwall.threat_intel.models import ThreatIndicatorType
from blackwall.threat_intel.otx import (
    AlienVaultOTXProvider,
    OTXCircuitBreakerOpenError,
    OTXTokenBucket,
)


@pytest.mark.asyncio
async def test_otx_token_bucket_acquire_and_replenish() -> None:
    # 5 capacity, 0.05s replenishment for fast testing
    bucket = OTXTokenBucket(capacity=5, replenishment_interval=0.05)
    assert bucket.get_available_tokens() == 5

    # Consume all 5
    for _ in range(5):
        assert await bucket.try_acquire() is True

    assert bucket.get_available_tokens() == 0
    # Next acquire should fail (budget exhausted)
    assert await bucket.try_acquire() is False

    # Wait for replenishment
    await asyncio.sleep(0.12)
    assert bucket.get_available_tokens() >= 2
    assert await bucket.try_acquire() is True


@pytest.mark.asyncio
async def test_otx_provider_initialization() -> None:
    provider = AlienVaultOTXProvider(api_key="test-otx-key")
    assert provider.name == "otx"
    assert ThreatIndicatorType.IPV4 in provider.supported_indicators
    assert ThreatIndicatorType.FILE_HASH in provider.supported_indicators
    assert provider.get_remaining_budget() == 10000
    assert await provider.is_healthy() is True


@pytest.mark.asyncio
async def test_otx_provider_lookup_ipv4_benign() -> None:
    provider = AlienVaultOTXProvider(api_key="test-otx-key")

    mock_response = {
        "indicator": "8.8.8.8",
        "type": "IPv4",
        "pulse_info": {
            "count": 0,
            "pulses": [],
        },
    }

    with patch.object(
        provider, "_execute_http_get", new_callable=AsyncMock
    ) as mock_get:
        mock_get.return_value = mock_response

        resp = await provider.lookup("8.8.8.8", ThreatIndicatorType.IPV4)
        assert resp.indicator == "8.8.8.8"
        assert resp.indicator_type == ThreatIndicatorType.IPV4
        assert resp.is_malicious is False
        assert resp.risk_score == 0.0
        assert resp.pulse_count == 0
        assert resp.provider_name == "otx"
        mock_get.assert_called_once_with("indicators/IPv4/8.8.8.8/general")


@pytest.mark.asyncio
async def test_otx_provider_lookup_domain_malicious_pulses() -> None:
    provider = AlienVaultOTXProvider(api_key="test-otx-key")

    mock_response = {
        "indicator": "malicious-c2.xyz",
        "type": "domain",
        "pulse_info": {
            "count": 3,
            "pulses": [
                {
                    "name": "Cobalt Strike C2 Infrastructure",
                    "tags": ["cobalt strike", "c2", "trojan"],
                    "malware_families": [{"display_name": "Cobalt Strike"}],
                    "references": ["https://threat.report/123"],
                },
                {
                    "name": "Lumma Stealer Drop",
                    "tags": ["stealer", "infostealer"],
                    "malware_families": [{"display_name": "Lumma"}],
                    "references": ["https://threat.report/456"],
                },
            ],
        },
    }

    with patch.object(
        provider, "_execute_http_get", new_callable=AsyncMock
    ) as mock_get:
        mock_get.return_value = mock_response

        resp = await provider.lookup("malicious-c2.xyz", ThreatIndicatorType.DOMAIN)
        assert resp.indicator == "malicious-c2.xyz"
        assert resp.indicator_type == ThreatIndicatorType.DOMAIN
        assert resp.is_malicious is True
        assert resp.risk_score >= 0.50
        assert resp.pulse_count == 3
        assert "Cobalt Strike" in resp.malware_families
        assert "Lumma" in resp.malware_families
        assert "c2" in resp.threat_categories
        assert "https://threat.report/123" in resp.references


@pytest.mark.asyncio
async def test_otx_provider_lookup_file_hash() -> None:
    provider = AlienVaultOTXProvider(api_key="test-otx-key")

    mock_response = {
        "indicator": "44d88612fea8a8f36de82e1278abb02f",
        "type": "file",
        "pulse_info": {
            "count": 1,
            "pulses": [
                {
                    "name": "Eicar Test File",
                    "tags": ["eicar", "test"],
                    "malware_families": [],
                    "references": [],
                }
            ],
        },
    }

    with patch.object(
        provider, "_execute_http_get", new_callable=AsyncMock
    ) as mock_get:
        mock_get.return_value = mock_response

        resp = await provider.lookup(
            "44d88612fea8a8f36de82e1278abb02f", ThreatIndicatorType.FILE_HASH
        )
        assert resp.indicator == "44d88612fea8a8f36de82e1278abb02f"
        assert resp.indicator_type == ThreatIndicatorType.FILE_HASH
        assert resp.pulse_count == 1
        assert "eicar" in resp.threat_categories
        mock_get.assert_called_once_with(
            "indicators/file/44d88612fea8a8f36de82e1278abb02f/general"
        )


@pytest.mark.asyncio
async def test_otx_provider_circuit_breaker() -> None:
    provider = AlienVaultOTXProvider(api_key="test-otx-key", cooldown_seconds=0.1)

    with patch.object(
        provider, "_execute_http_get", new_callable=AsyncMock
    ) as mock_get:
        mock_get.side_effect = ConnectionError("Network down")

        # 5 consecutive failures should trip the breaker
        for _ in range(5):
            resp = await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)
            # Should return safe fallback without crashing
            assert resp.is_malicious is False
            assert resp.risk_score == 0.0

        assert provider.circuit_state == "OPEN"

        # Next call while OPEN should raise OTXCircuitBreakerOpenError or return fallback
        resp = await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)
        assert resp.is_malicious is False

        # Wait for cooldown to transition to HALF-OPEN
        await asyncio.sleep(0.15)
        assert provider.circuit_state == "HALF-OPEN"

        # Successful call in HALF-OPEN should restore to CLOSED
        mock_get.side_effect = None
        mock_get.return_value = {"indicator": "1.2.3.4", "pulse_info": {"count": 0}}
        resp = await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)
        assert provider.circuit_state == "CLOSED"

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from blackwall.threat_intel.models import ThreatIndicatorType
from blackwall.threat_intel.otx import (
    AlienVaultOTXProvider,
    OTXCircuitBreakerOpenError,
    OTXLookupError,
    OTXTokenBucket,
    OTXTokenBucketExhaustedError,
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
async def test_otx_provider_circuit_breaker_three_probe_recovery() -> None:
    provider = AlienVaultOTXProvider(api_key="test-otx-key", cooldown_seconds=0.1)

    with patch.object(
        provider, "_execute_http_get", new_callable=AsyncMock
    ) as mock_get:
        mock_get.side_effect = ConnectionError("Network down")

        # 5 consecutive failures should trip the breaker to OPEN
        for _ in range(5):
            with pytest.raises(OTXLookupError):
                await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)

        assert provider.circuit_state == "OPEN"

        # While OPEN, lookup() must raise OTXCircuitBreakerOpenError (not look benign)
        with pytest.raises(OTXCircuitBreakerOpenError):
            await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)

        # Wait for cooldown to transition to HALF-OPEN
        await asyncio.sleep(0.15)
        assert provider.circuit_state == "HALF-OPEN"

        # Reset mock for successful responses
        mock_get.side_effect = None
        mock_get.return_value = {"indicator": "1.2.3.4", "pulse_info": {"count": 0}}

        # Probe 1: must remain HALF-OPEN
        await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)
        assert provider.circuit_state == "HALF-OPEN"

        # Probe 2: must remain HALF-OPEN
        await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)
        assert provider.circuit_state == "HALF-OPEN"

        # Probe 3: must restore circuit to CLOSED
        await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)
        assert provider.circuit_state == "CLOSED"


@pytest.mark.asyncio
async def test_otx_circuit_breaker_failure_during_half_open() -> None:
    provider = AlienVaultOTXProvider(api_key="test-otx-key", cooldown_seconds=0.1)

    with patch.object(
        provider, "_execute_http_get", new_callable=AsyncMock
    ) as mock_get:
        mock_get.side_effect = ConnectionError("Network down")
        for _ in range(5):
            with pytest.raises(OTXLookupError):
                await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)

        assert provider.circuit_state == "OPEN"
        await asyncio.sleep(0.15)
        assert provider.circuit_state == "HALF-OPEN"

        # Single failure during HALF-OPEN must immediately reset circuit to OPEN
        with pytest.raises(OTXLookupError):
            await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)

        assert provider._circuit_state == "OPEN"


@pytest.mark.asyncio
async def test_otx_token_bucket_exhaustion_raises_error() -> None:
    provider = AlienVaultOTXProvider(api_key="test-otx-key")
    # Drain token bucket
    provider.token_bucket.tokens = 0.0

    with pytest.raises(OTXTokenBucketExhaustedError):
        await provider.lookup("1.2.3.4", ThreatIndicatorType.IPV4)


def test_otx_provider_reads_config_yaml(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # Clear env var
    monkeypatch.delenv("BW_OTX_API_KEY", raising=False)

    fake_config_file = tmp_path / "config.yaml"
    fake_config_file.write_text("threat_intel:\n  otx_api_key: yaml-secret-key-123\n")

    with patch("os.path.expanduser", return_value=str(fake_config_file)):
        provider = AlienVaultOTXProvider()
        assert provider.api_key == "yaml-secret-key-123"
        assert provider.get_remaining_budget() == 10000


def test_otx_provider_unauthenticated_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("BW_OTX_API_KEY", raising=False)

    with patch("os.path.exists", return_value=False):
        with caplog.at_level("WARNING"):
            provider = AlienVaultOTXProvider()
            assert provider.api_key == ""
            assert provider.get_remaining_budget() == 1000
            assert any("No AlienVault OTX API key configured" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_otx_indicator_sanitization_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    provider = AlienVaultOTXProvider(api_key="test-otx-key")
    provider.token_bucket.tokens = 0.0

    sensitive_url = "https://admin:super_secret_password@badc2.net:8443/stealer/gate.php?token=secret_agent_token_999#leak"

    with caplog.at_level("WARNING"):
        with pytest.raises(OTXTokenBucketExhaustedError) as exc_info:
            await provider.lookup(sensitive_url, ThreatIndicatorType.URL)

        # Ensure credentials and tokens do not appear in exception message or logs
        assert "super_secret_password" not in str(exc_info.value)
        assert "secret_agent_token_999" not in str(exc_info.value)
        assert not any("super_secret_password" in rec.message for rec in caplog.records)
        assert not any("secret_agent_token_999" in rec.message for rec in caplog.records)


from __future__ import annotations

from unittest.mock import AsyncMock, patch
import pytest

from blackwall.threat_intel.abusech import (
    AbuseChLookupError,
    AbuseChProvider,
    AbuseChRateLimitError,
)

from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelProvider,
)


@pytest.mark.asyncio
async def test_abusech_initialization() -> None:
    provider = AbuseChProvider(auth_key="test-auth-key")
    assert provider.name == "abusech"
    assert ThreatIndicatorType.IPV4 in provider.supported_indicators
    assert ThreatIndicatorType.IPV6 in provider.supported_indicators
    assert ThreatIndicatorType.DOMAIN in provider.supported_indicators
    assert ThreatIndicatorType.URL in provider.supported_indicators
    assert ThreatIndicatorType.FILE_HASH in provider.supported_indicators
    assert provider.get_remaining_budget() > 0
    assert await provider.is_healthy() is True
    assert isinstance(provider, ThreatIntelProvider)


@pytest.mark.asyncio
async def test_abusech_initialization_without_auth_key() -> None:
    with patch.dict("os.environ", {}, clear=True), patch("os.path.exists", return_value=False):
        provider = AbuseChProvider(auth_key=None)
        assert provider.auth_key == ""
        assert await provider.is_healthy() is True
        assert provider.get_remaining_budget() > 0


@pytest.mark.asyncio
async def test_abusech_threatfox_ip_malicious() -> None:
    provider = AbuseChProvider(auth_key="test-key")

    mock_response = {
        "query_status": "ok",
        "data": [
            {
                "id": "123456",
                "ioc": "198.51.100.42:443",
                "threat_type": "botnet_cc",
                "threat_type_desc": "Botnet Command and Control",
                "ioc_type": "ip:port",
                "malware": "win.cobalt_strike",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 95,
                "first_seen": "2026-09-10 10:00:00 UTC",
                "last_seen": "2026-09-16 12:00:00 UTC",
                "reporter": "threat_researcher",
                "tags": ["CobaltStrike", "c2", "beacon"],
            }
        ],
    }

    with patch.object(provider, "_execute_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        resp = await provider.lookup("198.51.100.42", ThreatIndicatorType.IPV4)
        assert resp.indicator == "198.51.100.42"
        assert resp.indicator_type == ThreatIndicatorType.IPV4
        assert resp.is_malicious is True
        assert resp.risk_score == 0.95
        assert "Cobalt Strike" in resp.malware_families
        assert any("cobaltstrike" in t.lower() or "c2" in t.lower() for t in resp.threat_categories)
        assert resp.provider_name == "abusech"


@pytest.mark.asyncio
async def test_abusech_threatfox_benign() -> None:
    provider = AbuseChProvider(auth_key="test-key")

    mock_response = {
        "query_status": "no_result",
        "data": [],
    }

    with patch.object(provider, "_execute_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        resp = await provider.lookup("8.8.8.8", ThreatIndicatorType.IPV4)
        assert resp.indicator == "8.8.8.8"
        assert resp.is_malicious is False
        assert resp.risk_score == 0.0
        assert resp.detection_count == 0
        assert resp.malware_families == []


@pytest.mark.asyncio
async def test_abusech_urlhaus_url_malicious() -> None:
    provider = AbuseChProvider(auth_key="test-key")

    mock_response = {
        "query_status": "ok",
        "id": "78910",
        "url": "http://evil-payload-site.xyz/malware.bin",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["elf", "Mirai"],
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/78910/",
        "reporter": "abuse_hunter",
    }

    with patch.object(provider, "_execute_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        resp = await provider.lookup(
            "http://evil-payload-site.xyz/malware.bin", ThreatIndicatorType.URL
        )
        assert resp.indicator == "http://evil-payload-site.xyz/malware.bin"
        assert resp.indicator_type == ThreatIndicatorType.URL
        assert resp.is_malicious is True
        assert resp.risk_score >= 0.9
        assert any("mirai" in t.lower() or "malware_download" in t.lower() for t in resp.threat_categories)
        assert "https://urlhaus.abuse.ch/url/78910/" in resp.references


@pytest.mark.asyncio
async def test_abusech_urlhaus_url_benign() -> None:
    provider = AbuseChProvider(auth_key="test-key")

    mock_response = {
        "query_status": "no_results",
    }

    with patch.object(provider, "_execute_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        resp = await provider.lookup(
            "https://clean-site.org/index.html", ThreatIndicatorType.URL
        )
        assert resp.indicator == "https://clean-site.org/index.html"
        assert resp.is_malicious is False
        assert resp.risk_score == 0.0


@pytest.mark.asyncio
async def test_abusech_malwarebazaar_hash_malicious() -> None:
    provider = AbuseChProvider(auth_key="test-key")

    mock_response = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "44d88612fea8a8f36de82e1278abb02f1234567890abcdef1234567890abcdef",
                "file_name": "invoice_dropper.exe",
                "signature": "QakBot",
                "tags": ["exe", "QakBot", "trojan"],
                "reporter": "malware_analyst",
            }
        ],
    }

    with patch.object(provider, "_execute_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        resp = await provider.lookup(
            "44d88612fea8a8f36de82e1278abb02f1234567890abcdef1234567890abcdef",
            ThreatIndicatorType.FILE_HASH,
        )
        assert resp.is_malicious is True
        assert resp.risk_score >= 0.9
        assert "QakBot" in resp.malware_families
        assert any("trojan" in t.lower() for t in resp.threat_categories)


@pytest.mark.asyncio
async def test_abusech_malwarebazaar_hash_benign() -> None:
    provider = AbuseChProvider(auth_key="test-key")

    mock_response = {
        "query_status": "hash_not_found",
    }

    with patch.object(provider, "_execute_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        resp = await provider.lookup(
            "0000000000000000000000000000000000000000000000000000000000000000",
            ThreatIndicatorType.FILE_HASH,
        )
        assert resp.is_malicious is False
        assert resp.risk_score == 0.0


@pytest.mark.asyncio
async def test_abusech_rate_limit_and_error_handling() -> None:
    provider = AbuseChProvider(auth_key="test-key")

    with patch.object(
        provider, "_execute_post", side_effect=AbuseChRateLimitError("Rate limit 429")
    ):
        with pytest.raises(AbuseChLookupError, match="rate limit"):
            await provider.lookup("test-c2.com", ThreatIndicatorType.DOMAIN)


@pytest.mark.asyncio
async def test_abusech_url_credential_sanitization_in_errors(
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider = AbuseChProvider(auth_key="test-key")
    user_part = "mock_user"
    pass_part = "mock_pass"
    token_part = "mock_token"
    sensitive_url = (
        f"https://{user_part}:{pass_part}@malicious-c2.xyz/payload.bin?api_key={token_part}#frag"
    )

    with patch.object(
        provider, "_execute_post", side_effect=ConnectionError("Failed connection")
    ):
        with pytest.raises(AbuseChLookupError) as exc_info:
            await provider.lookup(sensitive_url, ThreatIndicatorType.URL)

        # Assert credentials and tokens are redacted from exception message
        err_msg = str(exc_info.value)
        assert pass_part not in err_msg
        assert token_part not in err_msg
        assert "[REDACTED]" in err_msg

        # Assert credentials and tokens are redacted from logs
        assert pass_part not in caplog.text
        assert token_part not in caplog.text


@pytest.mark.asyncio
async def test_abusech_null_and_malformed_response_handling() -> None:
    provider = AbuseChProvider(auth_key="test-key")

    # ThreatFox returns data: None
    with patch.object(provider, "_execute_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = {"query_status": "ok", "data": None}
        resp = await provider.lookup("1.1.1.1", ThreatIndicatorType.IPV4)
        assert resp.risk_score == 0.0
        assert resp.is_malicious is False
        assert resp.malware_families == []

    # MalwareBazaar returns data: None
    with patch.object(provider, "_execute_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = {"query_status": "ok", "data": None}
        resp = await provider.lookup("44d88612fea8a8f36de82e1278abb02f", ThreatIndicatorType.FILE_HASH)
        assert resp.risk_score == 1.0
        assert resp.is_malicious is True
        assert resp.malware_families == []


@pytest.mark.asyncio
async def test_abusech_indicator_whitespace_and_hash_normalization() -> None:
    provider = AbuseChProvider(auth_key="test-key")

    with patch.object(provider, "_execute_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = {"query_status": "no_result"}
        resp = await provider.lookup("   1.1.1.1   \n", ThreatIndicatorType.IPV4)
        assert resp.indicator == "1.1.1.1"

    # Hash should be lowercased
    with patch.object(provider, "_execute_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = {"query_status": "hash_not_found"}
        resp = await provider.lookup("  44D88612FEA8A8F36DE82E1278ABB02F  ", ThreatIndicatorType.FILE_HASH)
        assert resp.indicator == "44d88612fea8a8f36de82e1278abb02f"

    with pytest.raises(ValueError, match="Indicator cannot be empty"):
        await provider.lookup("   \t  ", ThreatIndicatorType.IPV4)


@pytest.mark.asyncio
async def test_abusech_rate_limit_subclass_catchable() -> None:
    provider = AbuseChProvider(auth_key="test-key")

    with patch.object(
        provider, "_execute_post", side_effect=AbuseChRateLimitError("429")
    ):
        with pytest.raises(AbuseChRateLimitError):
            await provider.lookup("test-c2.com", ThreatIndicatorType.DOMAIN)

    with patch.object(
        provider, "_execute_post", side_effect=AbuseChRateLimitError("429")
    ):
        with pytest.raises(AbuseChLookupError):
            await provider.lookup("test-c2.com", ThreatIndicatorType.DOMAIN)



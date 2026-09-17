"""Unit tests for Harpoon OSINT Companion Bridge (Track F)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from blackwall.threat_intel.harpoon import (
    HarpoonBridge,
    HarpoonError,
    HarpoonExecutionError,
    HarpoonTimeoutError,
)
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelProvider,
    ThreatIntelResponse,
)
from blackwall.threat_intel.otx import AlienVaultOTXProvider


def test_harpoon_exception_hierarchy() -> None:
    err = HarpoonExecutionError("process failed")
    assert isinstance(err, HarpoonError)
    assert isinstance(err, Exception)


@pytest.fixture
def mock_otx_fallback() -> MagicMock:
    fallback = MagicMock(spec=AlienVaultOTXProvider)
    fallback.name = "otx"
    fallback.supported_indicators = {
        ThreatIndicatorType.IPV4,
        ThreatIndicatorType.IPV6,
        ThreatIndicatorType.DOMAIN,
        ThreatIndicatorType.URL,
        ThreatIndicatorType.FILE_HASH,
    }
    fallback.lookup = AsyncMock(
        return_value=ThreatIntelResponse(
            indicator="198.51.100.1",
            indicator_type=ThreatIndicatorType.IPV4,
            is_malicious=False,
            risk_score=0.0,
            pulse_count=0,
            provider_name="otx",
        )
    )
    fallback.is_healthy = AsyncMock(return_value=True)
    fallback.get_remaining_budget = MagicMock(return_value=10000)
    return fallback


def test_harpoon_bridge_implements_protocol() -> None:
    bridge = HarpoonBridge()
    assert isinstance(bridge, ThreatIntelProvider)
    assert bridge.name == "harpoon"
    assert ThreatIndicatorType.IPV4 in bridge.supported_indicators
    assert ThreatIndicatorType.DOMAIN in bridge.supported_indicators
    assert ThreatIndicatorType.FILE_HASH in bridge.supported_indicators


def test_harpoon_liveness_detection_present() -> None:
    bridge = HarpoonBridge()
    with patch("shutil.which", return_value="/usr/local/bin/harpoon"):
        assert bridge.is_available() is True


def test_harpoon_liveness_detection_absent() -> None:
    bridge = HarpoonBridge()
    with patch("shutil.which", return_value=None):
        assert bridge.is_available() is False


@pytest.mark.asyncio
async def test_harpoon_subprocess_execution_success() -> None:
    bridge = HarpoonBridge()
    sample_json = (
        b'{"indicator": "198.51.100.1", "pulse_info": {"count": 2, "pulses": ['
        b'{"name": "Cobalt Strike C2", "tags": ["c2", "malware"], "malware_families": [{"display_name": "Cobalt Strike"}], "references": ["https://example.com/c2"]}'
        b"]}}"
    )

    mock_proc = AsyncMock()
    mock_proc.communicate.return_value = (sample_json, b"")
    mock_proc.returncode = 0

    with patch("shutil.which", return_value="/usr/local/bin/harpoon"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            resp = await bridge.lookup("198.51.100.1", ThreatIndicatorType.IPV4)

            assert mock_exec.called
            args = mock_exec.call_args[0]
            assert args[0] == "harpoon"
            assert args[1] == "otx"
            assert args[2] == "ip"
            assert args[3] == "198.51.100.1"
            assert args[4] == "--json"

            assert resp.indicator == "198.51.100.1"
            assert resp.indicator_type == ThreatIndicatorType.IPV4
            assert resp.is_malicious is True
            assert resp.risk_score >= 0.50
            assert resp.pulse_count == 2
            assert "Cobalt Strike" in resp.malware_families
            assert "c2" in resp.threat_categories
            assert resp.provider_name == "harpoon"


@pytest.mark.asyncio
async def test_harpoon_indicator_subcommand_mapping() -> None:
    bridge = HarpoonBridge()
    mappings = [
        (ThreatIndicatorType.IPV4, "1.1.1.1", "ip"),
        (ThreatIndicatorType.IPV6, "2001:db8::1", "ip"),
        (ThreatIndicatorType.DOMAIN, "evil.com", "domain"),
        (ThreatIndicatorType.URL, "http://evil.com/a", "url"),
        (ThreatIndicatorType.FILE_HASH, "d41d8cd98f00b204e9800998ecf8427e", "hash"),
    ]

    for ind_type, indicator, expected_subcmd in mappings:
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b'{"pulse_info": {"count": 0, "pulses": []}}', b"")
        mock_proc.returncode = 0

        with patch("shutil.which", return_value="/usr/local/bin/harpoon"):
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
                await bridge.lookup(indicator, ind_type)
                args = mock_exec.call_args[0]
                assert args[2] == expected_subcmd


@pytest.mark.asyncio
async def test_harpoon_timeout_enforced() -> None:
    bridge = HarpoonBridge()

    mock_proc = AsyncMock()

    async def slow_communicate():
        await asyncio.sleep(0.1)
        return (b"{}", b"")

    mock_proc.communicate = slow_communicate
    mock_proc.kill = MagicMock()

    with patch("shutil.which", return_value="/usr/local/bin/harpoon"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with pytest.raises(HarpoonTimeoutError):
                await bridge._execute_harpoon("ip", "1.1.1.1", timeout=0.01)


@pytest.mark.asyncio
async def test_harpoon_transparent_fallback_when_binary_absent(
    mock_otx_fallback: MagicMock,
) -> None:
    bridge = HarpoonBridge(fallback_provider=mock_otx_fallback)

    with patch("shutil.which", return_value=None):
        with patch("logging.Logger.info") as mock_log:
            resp = await bridge.lookup("198.51.100.1", ThreatIndicatorType.IPV4)
            assert resp.provider_name == "otx"
            mock_otx_fallback.lookup.assert_called_once_with(
                "198.51.100.1", ThreatIndicatorType.IPV4, timeout=5.0
            )
            # Log notice about fallback
            assert any("harpoon" in str(c).lower() for c in mock_log.call_args_list)


@pytest.mark.asyncio
async def test_harpoon_transparent_fallback_on_subprocess_error(
    mock_otx_fallback: MagicMock,
) -> None:
    bridge = HarpoonBridge(fallback_provider=mock_otx_fallback)

    mock_proc = AsyncMock()
    mock_proc.communicate.return_value = (b"", b"harpoon internal error")
    mock_proc.returncode = 1

    with patch("shutil.which", return_value="/usr/local/bin/harpoon"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            resp = await bridge.lookup("198.51.100.1", ThreatIndicatorType.IPV4)
            assert resp.provider_name == "otx"
            mock_otx_fallback.lookup.assert_called_once()


@pytest.mark.asyncio
async def test_harpoon_transparent_fallback_on_malformed_json(
    mock_otx_fallback: MagicMock,
) -> None:
    bridge = HarpoonBridge(fallback_provider=mock_otx_fallback)

    mock_proc = AsyncMock()
    mock_proc.communicate.return_value = (b"<html>404 Not Found</html>", b"")
    mock_proc.returncode = 0

    with patch("shutil.which", return_value="/usr/local/bin/harpoon"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            resp = await bridge.lookup("198.51.100.1", ThreatIndicatorType.IPV4)
            assert resp.provider_name == "otx"
            mock_otx_fallback.lookup.assert_called_once()

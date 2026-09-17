"""Unit tests for Native Blackwall CLI Suite (Track E)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
from click.testing import CliRunner
import pytest

from blackwall.cli import cli, detect_indicator_type
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)


def test_detect_indicator_type_ipv4() -> None:
    assert detect_indicator_type("198.51.100.1") == ThreatIndicatorType.IPV4
    assert detect_indicator_type("8.8.8.8") == ThreatIndicatorType.IPV4
    assert detect_indicator_type("127.0.0.1") == ThreatIndicatorType.IPV4


def test_detect_indicator_type_ipv6() -> None:
    assert detect_indicator_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == ThreatIndicatorType.IPV6
    assert detect_indicator_type("2001:db8::1") == ThreatIndicatorType.IPV6
    assert detect_indicator_type("::1") == ThreatIndicatorType.IPV6


def test_detect_indicator_type_domain() -> None:
    assert detect_indicator_type("malicious-c2.xyz") == ThreatIndicatorType.DOMAIN
    assert detect_indicator_type("api.threat-intel.co.uk") == ThreatIndicatorType.DOMAIN
    assert detect_indicator_type("phish-login.com") == ThreatIndicatorType.DOMAIN


def test_detect_indicator_type_url() -> None:
    assert detect_indicator_type("http://example.com/login") == ThreatIndicatorType.URL
    assert detect_indicator_type("https://evil.com/payload.exe") == ThreatIndicatorType.URL
    assert detect_indicator_type("ftp://evil.com/drop") == ThreatIndicatorType.URL


def test_detect_indicator_type_hashes() -> None:
    # MD5 (32 hex)
    assert detect_indicator_type("44d88612fea8a8f36de82e1278abb02f") == ThreatIndicatorType.FILE_HASH
    # SHA1 (40 hex)
    assert detect_indicator_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == ThreatIndicatorType.FILE_HASH
    # SHA256 (64 hex)
    assert detect_indicator_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == ThreatIndicatorType.FILE_HASH


def test_detect_indicator_type_invalid() -> None:
    with pytest.raises(ValueError, match="Could not automatically detect indicator type"):
        detect_indicator_type("!!!not-a-valid-indicator???")


@pytest.fixture
def mock_orchestrator() -> MagicMock:
    orch = MagicMock()
    orch.lookup = AsyncMock(
        return_value=ThreatIntelResponse(
            indicator="malicious-c2.xyz",
            indicator_type=ThreatIndicatorType.DOMAIN,
            is_malicious=True,
            risk_score=0.75,
            detection_count=1,
            total_engines=3,
            pulse_count=3,
            threat_categories=["c2", "trojan"],
            malware_families=["Cobalt Strike"],
            references=["https://otx.alienvault.com/pulse/123"],
            provider_name="otx",
            cached=False,
        )
    )
    orch.get_pulse = AsyncMock(
        return_value={
            "id": "pulse-12345",
            "name": "Cobalt Strike Infrastructure",
            "description": "Observed active C2 domain",
            "author_name": "AlienVault",
            "created": "2026-03-01T00:00:00",
            "modified": "2026-03-02T00:00:00",
            "tags": ["c2", "cobalt strike", "apt"],
            "malware_families": ["Cobalt Strike"],
            "adversary": "APT29",
            "references": ["https://attack.mitre.org/groups/G0016/"],
            "indicator_count": 14,
        }
    )
    orch.get_cache_stats = AsyncMock(
        return_value={
            "total_entries": 42,
            "active_entries": 38,
            "expired_entries": 4,
            "malicious_entries": 12,
            "size_bytes": 16384,
            "hits": 150,
            "misses": 20,
        }
    )
    orch.clear_cache = AsyncMock(return_value=4)

    mock_otx = MagicMock()
    mock_otx.name = "otx"
    mock_otx.supported_indicators = {
        ThreatIndicatorType.IPV4,
        ThreatIndicatorType.IPV6,
        ThreatIndicatorType.DOMAIN,
        ThreatIndicatorType.URL,
        ThreatIndicatorType.FILE_HASH,
    }
    mock_otx.is_healthy = AsyncMock(return_value=True)
    mock_otx.get_remaining_budget = MagicMock(return_value=9850)
    mock_otx.circuit_state = "CLOSED"
    mock_otx.api_key = "test-secret-key-12345"

    orch.get_providers = MagicMock(return_value=[mock_otx])
    return orch


def test_cli_check_table_output(mock_orchestrator: MagicMock) -> None:
    runner = CliRunner()
    with patch("blackwall.cli.get_orchestrator", return_value=mock_orchestrator):
        result = runner.invoke(cli, ["check", "malicious-c2.xyz"])
        assert result.exit_code == 0
        assert "BLOCK" in result.output
        assert "0.75" in result.output
        assert "otx" in result.output
        assert "malicious-c2.xyz" in result.output


def test_cli_check_json_output(mock_orchestrator: MagicMock) -> None:
    runner = CliRunner()
    with patch("blackwall.cli.get_orchestrator", return_value=mock_orchestrator):
        result = runner.invoke(cli, ["check", "malicious-c2.xyz", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["indicator"] == "malicious-c2.xyz"
        assert data["verdict"] == "BLOCK"
        assert data["risk_score"] == 0.75
        assert data["pulse_count"] == 3
        assert data["provider_name"] == "otx"


def test_cli_check_benign_allow(mock_orchestrator: MagicMock) -> None:
    mock_orchestrator.lookup = AsyncMock(
        return_value=ThreatIntelResponse(
            indicator="8.8.8.8",
            indicator_type=ThreatIndicatorType.IPV4,
            is_malicious=False,
            risk_score=0.0,
            pulse_count=0,
            provider_name="otx",
        )
    )
    runner = CliRunner()
    with patch("blackwall.cli.get_orchestrator", return_value=mock_orchestrator):
        result = runner.invoke(cli, ["check", "8.8.8.8"])
        assert result.exit_code == 0
        assert "ALLOW" in result.output
        assert "0.0" in result.output


def test_cli_check_type_override(mock_orchestrator: MagicMock) -> None:
    runner = CliRunner()
    with patch("blackwall.cli.get_orchestrator", return_value=mock_orchestrator):
        result = runner.invoke(cli, ["check", "8.8.8.8", "--type", "ipv4"])
        assert result.exit_code == 0
        mock_orchestrator.lookup.assert_called_once()
        kwargs = mock_orchestrator.lookup.call_args.kwargs
        assert kwargs["indicator_type"] == ThreatIndicatorType.IPV4


def test_cli_check_invalid_indicator() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["check", "??invalid-indicator??"])
    assert result.exit_code != 0
    assert "Could not automatically detect indicator type" in result.output


def test_cli_threat_intel_lookup(mock_orchestrator: MagicMock) -> None:
    runner = CliRunner()
    with patch("blackwall.cli.get_orchestrator", return_value=mock_orchestrator):
        result = runner.invoke(
            cli,
            ["threat-intel", "lookup", "198.51.100.1", "--provider", "otx", "--no-cache"],
        )
        assert result.exit_code == 0
        assert "198.51.100.1" in result.output


def test_cli_threat_intel_pulse(mock_orchestrator: MagicMock) -> None:
    runner = CliRunner()
    with patch("blackwall.cli.get_orchestrator", return_value=mock_orchestrator):
        result = runner.invoke(cli, ["threat-intel", "pulse", "pulse-12345"])
        assert result.exit_code == 0
        assert "Cobalt Strike Infrastructure" in result.output
        assert "APT29" in result.output
        assert "AlienVault" in result.output


def test_cli_threat_intel_pulse_json(mock_orchestrator: MagicMock) -> None:
    runner = CliRunner()
    with patch("blackwall.cli.get_orchestrator", return_value=mock_orchestrator):
        result = runner.invoke(cli, ["threat-intel", "pulse", "pulse-12345", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["id"] == "pulse-12345"
        assert data["name"] == "Cobalt Strike Infrastructure"


def test_cli_threat_intel_cache_status_and_clear(mock_orchestrator: MagicMock) -> None:
    runner = CliRunner()
    with patch("blackwall.cli.get_orchestrator", return_value=mock_orchestrator):
        status_res = runner.invoke(cli, ["threat-intel", "cache", "status"])
        assert status_res.exit_code == 0
        assert "42" in status_res.output
        assert "12" in status_res.output

        clear_res = runner.invoke(cli, ["threat-intel", "cache", "clear", "--expired-only"])
        assert clear_res.exit_code == 0
        assert "4" in clear_res.output


def test_cli_threat_intel_providers_credential_hygiene(mock_orchestrator: MagicMock) -> None:
    runner = CliRunner()
    with patch("blackwall.cli.get_orchestrator", return_value=mock_orchestrator):
        result = runner.invoke(cli, ["threat-intel", "providers"])
        assert result.exit_code == 0
        assert "otx" in result.output
        assert "9850" in result.output
        # Critical security invariant: secret key MUST NOT leak!
        assert "test-secret-key-12345" not in result.output

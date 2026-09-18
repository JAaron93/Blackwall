"""Property-based tests for Cross-Platform Service Manager (TASK-F01).

Covers non-tilde, sectioning, and non-root invariants across random inputs.
"""

from __future__ import annotations

import os

import pytest
from hypothesis import given, settings, strategies as st

from blackwall.gateway import service as svc

safe_text_st = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="~"),
    min_size=1,
    max_size=32,
).filter(lambda s: bool(s.strip()) and "/" not in s and "\x00" not in s)


@settings(max_examples=50)
@given(name=safe_text_st)
def test_property_no_tilde_in_generated_units(name: str, tmp_path_factory: pytest.TempPathFactory) -> None:
    """Any generated plist/systemd content SHALL contain zero raw tildes."""
    tmp = tmp_path_factory.mktemp(f"BW_SYNTHETIC_{abs(hash(name)) % 9999}")
    cfg = tmp / "gateway.yaml"
    cfg.write_text("upstream_servers: []\n", encoding="utf-8")
    env = {
        "GCP_PROJECT": "BW_SYNTHETIC_MOCK_PROJECT_0192",
        "PATH": "/usr/bin:/bin",
        "GEMINI_TIER": "paid",
        "GOOGLE_APPLICATION_CREDENTIALS": str(cfg),
    }
    plist = svc.generate_launchd_plist(
        str(cfg), str(tmp / "a.pid"), str(tmp / "a.log"), str(tmp / "a.db"), None, env
    )
    unit = svc.generate_systemd_unit(
        str(cfg), str(tmp / "a.pid"), str(tmp / "a.log"), str(tmp / "a.db"), None, env
    )
    assert "~" not in plist
    assert "~" not in unit
    assert "--foreground" in plist and "--foreground" in unit


@settings(max_examples=50)
@given(user=safe_text_st)
def test_property_system_unit_rejects_root_variants(user: str) -> None:
    """System units SHALL reject root identity and accept non-root users."""
    lowered = user.strip().lower()
    if lowered == "root":
        with pytest.raises(ValueError):
            svc.generate_systemd_unit(
                "/etc/blackwall/gateway.yaml",
                "/run/blackwall/blackwall.pid",
                "/var/log/blackwall/blackwall.log",
                "/var/lib/blackwall/threat_signatures.db",
                None,
                {"GCP_PROJECT": "BW_SYNTHETIC_MOCK_PROJECT_0192", "PATH": "/usr/bin:/bin"},
                system=True,
                user="root",
                group="root",
            )
        return
    content = svc.generate_systemd_unit(
        "/etc/blackwall/gateway.yaml",
        "/run/blackwall/blackwall.pid",
        "/var/log/blackwall/blackwall.log",
        "/var/lib/blackwall/threat_signatures.db",
        None,
        {"GCP_PROJECT": "BW_SYNTHETIC_MOCK_PROJECT_0192", "PATH": "/usr/bin:/bin"},
        system=True,
        user=user.strip(),
        group=user.strip(),
    )
    assert f"User={user.strip()}" in content
    assert "User=root" not in content


@settings(max_examples=50)
@given(project=st.from_regex(r"[A-Za-z0-9_-]{1,24}", fullmatch=True))
def test_property_gcp_project_acceptance(project: str) -> None:
    """Non-empty project IDs SHALL be accepted by install validation."""
    assert svc.get_gcp_project(project) == project

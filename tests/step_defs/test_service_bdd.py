"""BDD Step Definitions for Cross-Platform Service Manager (TASK-F01).

Covers ``tests/features/blackwall_service.feature`` using generation-level
assertions (no launchctl/systemctl side effects on CI hosts).
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

scenarios("../features/blackwall_service.feature")


@pytest.fixture
def svc_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Per-scenario isolated service state with synthetic credentials."""
    adc = tmp_path / "adc.json"
    adc.write_text('{"client_id": "BW_SYNTHETIC_MOCK_CLIENT_0192"}', encoding="utf-8")
    monkeypatch.setenv("GCP_PROJECT", "BW_SYNTHETIC_MOCK_PROJECT_0192")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(adc))
    monkeypatch.setenv("GEMINI_TIER", "paid")
    cfg = tmp_path / "gateway.yaml"
    cfg.write_text("upstream_servers: []\n", encoding="utf-8")
    return {"tmp": tmp_path, "cfg": cfg, "adc": adc, "plist": None, "unit": None, "error": None}


@given("the Phase 5 service manager components are available")
def phase5_components_available() -> None:
    from blackwall.gateway import service as svc  # noqa: F401

    assert svc.LAUNCHD_LABEL == "com.blackwall.gateway"


@given("a macOS service install request with valid GCP project")
def macos_request(svc_state: dict[str, Any]) -> None:
    svc_state["platform"] = "darwin"


@given("a Linux service install request with valid GCP project")
def linux_request(svc_state: dict[str, Any]) -> None:
    svc_state["platform"] = "linux"


@given("a Linux system install request with derived service user")
def linux_system_request(svc_state: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SUDO_USER", raising=False)
    svc_state["platform"] = "linux"
    svc_state["system"] = True


@given("a service install request without GCP project")
def no_project_request(svc_state: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    svc_state["platform"] = "linux"


@when("the launchd plist is generated")
def gen_plist(svc_state: dict[str, Any]) -> None:
    from blackwall.gateway import service as svc

    tmp = svc_state["tmp"]
    svc_state["plist"] = svc.generate_launchd_plist(
        str(svc_state["cfg"]),
        str(tmp / "blackwall.pid"),
        str(tmp / "blackwall.log"),
        str(tmp / "threat_signatures.db"),
        None,
        {
            "GCP_PROJECT": os.environ["GCP_PROJECT"],
            "GOOGLE_APPLICATION_CREDENTIALS": os.environ["GOOGLE_APPLICATION_CREDENTIALS"],
            "GEMINI_TIER": "paid",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        },
    )


@when("the systemd user unit is generated")
def gen_user_unit(svc_state: dict[str, Any]) -> None:
    from blackwall.gateway import service as svc

    tmp = svc_state["tmp"]
    svc_state["unit"] = svc.generate_systemd_unit(
        str(svc_state["cfg"]),
        str(tmp / "blackwall.pid"),
        str(tmp / "blackwall.log"),
        str(tmp / "threat_signatures.db"),
        None,
        {
            "GCP_PROJECT": os.environ["GCP_PROJECT"],
            "GOOGLE_APPLICATION_CREDENTIALS": os.environ["GOOGLE_APPLICATION_CREDENTIALS"],
            "GEMINI_TIER": "paid",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        },
        system=False,
    )


@when("the systemd system unit is generated")
def gen_system_unit(svc_state: dict[str, Any]) -> None:
    from blackwall.gateway import service as svc

    user, group = svc.derive_system_user(None)
    svc_state["derived_user"] = user
    svc_state["unit"] = svc.generate_systemd_unit(
        "/etc/blackwall/gateway.yaml",
        "/run/blackwall/blackwall.pid",
        "/var/log/blackwall/blackwall.log",
        "/var/lib/blackwall/threat_signatures.db",
        None,
        {
            "GCP_PROJECT": os.environ["GCP_PROJECT"],
            "GOOGLE_APPLICATION_CREDENTIALS": os.environ["GOOGLE_APPLICATION_CREDENTIALS"],
            "GEMINI_TIER": "paid",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        },
        system=True,
        user=user,
        group=group,
    )


@when("install is attempted")
def attempt_install(svc_state: dict[str, Any]) -> None:
    from blackwall.gateway import service as svc

    try:
        svc.install_service(
            config_path=None,
            wrap_cmd=None,
            project=None,
            credentials=None,
            system=False,
            platform_override="linux",
            home=svc_state["tmp"],
            output_path=svc_state["tmp"] / "blackwall.service",
        )
    except ValueError as exc:
        svc_state["error"] = str(exc)


@then("the plist is valid XML supervising serve foreground with throttle guards")
def check_plist(svc_state: dict[str, Any]) -> None:
    plist = svc_state["plist"]
    ET.fromstring(plist)
    assert "serve" in plist and "--foreground" in plist
    assert "<integer>30</integer>" in plist
    assert "SuccessfulExit" in plist


@then("the plist embeds GCP credentials and upstream config with zero tildes")
def check_plist_env(svc_state: dict[str, Any]) -> None:
    plist = svc_state["plist"]
    assert "GCP_PROJECT" in plist
    assert "--config" in plist
    assert "~" not in plist


@then("rate limits are under Unit and supervision bounds under Service")
def check_sectioning(svc_state: dict[str, Any]) -> None:
    unit = svc_state["unit"]
    unit_section = unit.split("[Service]")[0]
    service_section = unit.split("[Service]")[1]
    assert "StartLimitBurst=5" in unit_section
    assert "StartLimitIntervalSec=60s" in unit_section
    assert "Type=exec" in service_section
    assert "MemoryMax=350M" in service_section


@then("the unit ExecStart includes foreground and FHS-resolved flags")
def check_execstart(svc_state: dict[str, Any]) -> None:
    unit = svc_state["unit"]
    assert "--foreground" in unit
    assert "--pidfile" in unit and "--logfile" in unit
    assert "~" not in unit


@then("the unit configures non-root User and FHS directories")
def check_system_unit(svc_state: dict[str, Any]) -> None:
    unit = svc_state["unit"]
    assert f"User={svc_state['derived_user']}" in unit
    assert "User=root" not in unit
    assert "RuntimeDirectory=blackwall" in unit
    assert "StateDirectory=blackwall" in unit
    assert "EnvironmentFile=-/etc/default/blackwall" in unit


@then("User root is strictly rejected")
def check_root_rejected() -> None:
    from blackwall.gateway import service as svc

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


@then("installation fails with a clear error")
def check_install_fails(svc_state: dict[str, Any]) -> None:
    assert svc_state["error"] is not None
    assert "GCP" in svc_state["error"]

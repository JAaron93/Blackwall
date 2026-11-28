"""BDD steps for tests/features/macos_service_manager.feature (TASK-F01)."""

from __future__ import annotations

import plistlib
import stat
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.cli import cli

scenarios("../features/macos_service_manager.feature")

SECRET = "TS_SYNTHETIC_BDD_KEY_FOR_TESTS_9876543210"


class ServiceBDDState:
    def __init__(self) -> None:
        self.home: Path | None = None
        self.result: Any = None


@pytest.fixture()
def state() -> ServiceBDDState:
    return ServiceBDDState()


@pytest.fixture()
def isolated_home(tmp_path: Path, state: ServiceBDDState) -> Path:
    home = tmp_path / "home"
    adc = home / ".config" / "gcloud"
    adc.mkdir(parents=True)
    (adc / "application_default_credentials.json").write_text("{}")
    state.home = home
    return home


def _argv(command: str) -> list[str]:
    """Strip the human-readable executable prefix from a Gherkin command."""
    parts = command.split()
    return parts[1:] if parts and parts[0] == "blackwall" else parts


def _cli_env(home: Path, **overrides: str) -> dict[str, str]:
    env: dict[str, str] = {
        "HOME": str(home),
        "GCP_PROJECT": "bdd-project",
        "GOOGLE_CLOUD_PROJECT": "",
        "GOOGLE_APPLICATION_CREDENTIALS": "",
        "TYPESAFE_API_KEY": "",
        "BW_SKIP_GCP_CHECK": "",
    }
    env.update(overrides)
    return env


@given("an isolated macOS home with standard gcloud ADC", target_fixture="home")
def given_isolated_home(isolated_home: Path) -> Path:
    return isolated_home


@when(parsers.parse('the user runs "{command}"'))
def when_install(command: str, state: ServiceBDDState, home: Path) -> None:
    state.result = CliRunner().invoke(
        cli, _argv(command), env=_cli_env(home)
    )


@when(parsers.parse('the user runs "{command}" without a GCP project'))
def when_install_without_project(command: str, state: ServiceBDDState, home: Path) -> None:
    state.result = CliRunner().invoke(
        cli,
        _argv(command),
        env=_cli_env(home, GCP_PROJECT="", GOOGLE_CLOUD_PROJECT=""),
    )


@when(parsers.parse('the user runs "{command}" with a TypeSafe API key'))
def when_install_with_key(command: str, state: ServiceBDDState, home: Path) -> None:
    state.result = CliRunner().invoke(
        cli,
        _argv(command),
        env=_cli_env(home, TYPESAFE_API_KEY=SECRET),
    )


def _plist_path(home: Path) -> Path:
    return home / "Library" / "LaunchAgents" / "com.blackwall.gateway.plist"


@then("the generated LaunchAgent supervises the foreground gateway with absolute paths")
def then_supervised_plist(state: ServiceBDDState, home: Path) -> None:
    assert state.result.exit_code == 0, state.result.output
    data = plistlib.loads(_plist_path(home).read_bytes())
    assert data["RunAtLoad"] is True
    assert data["KeepAlive"] == {"SuccessfulExit": False}
    assert data["ThrottleInterval"] == 30
    assert "--foreground" in data["ProgramArguments"]
    assert all("~" not in value for value in data["ProgramArguments"])


@then("installation fails with an actionable GCP project error")
def then_fail_fast(state: ServiceBDDState, home: Path) -> None:
    assert state.result.exit_code != 0
    assert "GCP_PROJECT" in state.result.output
    assert not _plist_path(home).exists()


@then("the key exists only in a 0600 env file and never in the plist or CLI output")
def then_secret_isolated(state: ServiceBDDState, home: Path) -> None:
    assert state.result.exit_code == 0, state.result.output
    env_file = home / ".blackwall" / "gateway.env"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert SECRET in env_file.read_text()
    assert SECRET not in _plist_path(home).read_text()
    assert SECRET not in state.result.output

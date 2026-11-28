"""BDD steps for tests/features/audit_hook_bootstrap.feature (TASK-F02)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.audit import bootstrap
from blackwall.cli import cli

scenarios("../features/audit_hook_bootstrap.feature")

REPO_SRC = Path(__file__).resolve().parents[2] / "src"
ORIGINAL = b"# pre-existing customization\r\nVALUE = 99\r\n"


def _argv(command: str) -> list[str]:
    parts = command.split()
    return parts[1:] if parts and parts[0] == "blackwall" else parts


class HookBDDState:
    def __init__(self) -> None:
        self.site_dir: Path | None = None
        self.result: Any = None
        self.env: dict[str, str] = {}
        self.child: subprocess.CompletedProcess[str] | None = None


@pytest.fixture()
def state() -> HookBDDState:
    return HookBDDState()


@given("a mock Python site-packages directory with existing sitecustomize logic", target_fixture="site_dir")
def given_site_dir(tmp_path: Path, state: HookBDDState) -> Path:
    site_dir = tmp_path / "site-packages"
    site_dir.mkdir()
    (site_dir / "sitecustomize.py").write_bytes(ORIGINAL)
    state.site_dir = site_dir
    return site_dir


@given("a bootstrapped Python environment in an isolated home")
def given_bootstrapped(tmp_path: Path, state: HookBDDState) -> None:
    site_dir = tmp_path / "site-packages"
    site_dir.mkdir()
    bootstrap.install_hook([site_dir])
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(REPO_SRC), str(site_dir)])
    home = tmp_path / "home"
    home.mkdir()
    env["HOME"] = str(home)
    env.pop(bootstrap.DB_ENV, None)
    env.pop(bootstrap.DISABLE_ENV, None)
    state.site_dir = site_dir
    state.env = env


@when(parsers.parse('the user runs "{command}"'))
def when_install(command: str, state: HookBDDState, monkeypatch: pytest.MonkeyPatch) -> None:
    assert state.site_dir is not None
    monkeypatch.setattr(bootstrap, "discover_site_packages", lambda: [state.site_dir])
    state.result = CliRunner().invoke(cli, _argv(command))


@when("the user uninstalls the audit hook bootstrap")
def when_uninstall(state: HookBDDState, monkeypatch: pytest.MonkeyPatch) -> None:
    assert state.site_dir is not None
    monkeypatch.setattr(bootstrap, "discover_site_packages", lambda: [state.site_dir])
    assert CliRunner().invoke(cli, ["hook", "install"]).exit_code == 0
    bootstrap.uninstall_hook([state.site_dir])


@when(parsers.parse('a clean Python subprocess attempts "{payload}"'))
def when_child_payload(payload: str, state: HookBDDState) -> None:
    assert payload == "subprocess.Popen"
    code = (
        "import subprocess\n"
        "try:\n"
        "    subprocess.Popen(['/bin/echo', 'pwned'])\n"
        "except PermissionError:\n"
        "    print('BLOCKED')\n"
        "else:\n"
        "    print('ALLOWED')\n"
    )
    state.child = subprocess.run(
        [sys.executable, "-c", code],
        env=state.env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@then("the sitecustomize file contains the marked bootstrap and preserves the original logic")
def then_injected(state: HookBDDState) -> None:
    assert state.result.exit_code == 0, state.result.output
    assert state.site_dir is not None
    content = (state.site_dir / "sitecustomize.py").read_bytes()
    assert ORIGINAL in content
    assert bootstrap.BOOTSTRAP_START.encode() in content
    assert bootstrap.BOOTSTRAP_END.encode() in content


@then("the sitecustomize file is byte-for-byte identical to the original")
def then_restored(state: HookBDDState) -> None:
    assert state.site_dir is not None
    assert (state.site_dir / "sitecustomize.py").read_bytes() == ORIGINAL


@then(parsers.parse('the attempt raises "{exception}" before the OS executes it'))
def then_blocked(exception: str, state: HookBDDState) -> None:
    assert state.child is not None
    assert state.child.returncode == 0, state.child.stderr
    assert exception == "PermissionError"
    assert "BLOCKED" in state.child.stdout, (state.child.stdout, state.child.stderr)

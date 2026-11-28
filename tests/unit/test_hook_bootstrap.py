"""Unit and subprocess tests for Python audit hook auto-bootstrap (TASK-F02).

Hook registration is never performed at module import time; all registration
 either happens inside a patched unit test or in an isolated child process
 (`.agents/rules/testing_and_hygiene.md` §4).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from blackwall.audit import bootstrap
from blackwall.cli import cli

REPO_SRC = Path(__file__).resolve().parents[2] / "src"


@pytest.fixture(autouse=True)
def reset_bootstrap_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep hook-attachment state isolated between tests.

    An audit hook cannot be unregistered, so direct calls must never attach the
    real guard in the pytest process (`.agents/rules/testing_and_hygiene.md` §4).
    """
    monkeypatch.setattr(bootstrap, "_BOOTSTRAPPED", False)
    monkeypatch.setattr(bootstrap, "_GUARD_REGISTERED", False)
    monkeypatch.setattr(bootstrap, "_register_critical_guard", lambda: None)


@pytest.fixture()
def site_dir(tmp_path: Path) -> Path:
    target = tmp_path / "site-packages"
    target.mkdir()
    return target


def _child(code: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


class TestSnippetAndSitePackages:
    def test_snippet_is_marked_and_calls_bootstrap(self) -> None:
        snippet = bootstrap.generate_snippet()
        assert bootstrap.BOOTSTRAP_START in snippet
        assert bootstrap.BOOTSTRAP_END in snippet
        assert "bootstrap_audit_hook()" in snippet

    def test_install_preserves_existing_sitecustomize_content(self, site_dir: Path) -> None:
        sitecustomize = site_dir / "sitecustomize.py"
        sitecustomize.write_bytes(b"# existing customization\nVALUE = 42\n")

        bootstrap.install_hook([site_dir])
        content = sitecustomize.read_bytes()
        assert b"# existing customization\nVALUE = 42\n" in content
        assert bootstrap.BOOTSTRAP_START.encode() in content
        assert content.index(b"VALUE = 42") < content.index(
            bootstrap.BOOTSTRAP_START.encode()
        )

    def test_install_is_idempotent(self, site_dir: Path) -> None:
        bootstrap.install_hook([site_dir])
        bootstrap.install_hook([site_dir])
        text = (site_dir / "sitecustomize.py").read_text()
        assert text.count(bootstrap.BOOTSTRAP_START) == 1
        assert text.count(bootstrap.BOOTSTRAP_END) == 1

    def test_uninstall_restores_original_bytes_exactly(self, site_dir: Path) -> None:
        sitecustomize = site_dir / "sitecustomize.py"
        original = b"# custom\r\nVALUE = 7\r\n"
        sitecustomize.write_bytes(original)

        bootstrap.install_hook([site_dir])
        bootstrap.uninstall_hook([site_dir])
        assert sitecustomize.read_bytes() == original

    def test_uninstall_keeps_additions_in_file_created_by_install(
        self, site_dir: Path
    ) -> None:
        bootstrap.install_hook([site_dir])
        path = site_dir / "sitecustomize.py"
        addition = b"\n# added by user after install\nVALUE = 5\n"
        path.write_bytes(path.read_bytes() + addition)

        bootstrap.uninstall_hook([site_dir])
        assert path.is_file()
        assert addition in path.read_bytes()

    def test_uninstall_preserves_preexisting_empty_sitecustomize(
        self, site_dir: Path
    ) -> None:
        sitecustomize = site_dir / "sitecustomize.py"
        sitecustomize.write_bytes(b"")
        bootstrap.install_hook([site_dir])
        bootstrap.uninstall_hook([site_dir])
        assert sitecustomize.exists()
        assert sitecustomize.read_bytes() == b""

    def test_uninstall_removes_file_it_created(self, site_dir: Path) -> None:
        sitecustomize = site_dir / "sitecustomize.py"
        bootstrap.install_hook([site_dir])
        assert sitecustomize.exists()
        bootstrap.uninstall_hook([site_dir])
        assert not sitecustomize.exists()

    def test_uninstall_keeps_customizations_added_after_install(
        self, site_dir: Path
    ) -> None:
        sitecustomize = site_dir / "sitecustomize.py"
        original = b"VALUE = 1\n"
        sitecustomize.write_bytes(original)
        bootstrap.install_hook([site_dir])
        addition = b"\n# user addition after install\nVALUE = 2\n"
        sitecustomize.write_bytes(sitecustomize.read_bytes() + addition)

        bootstrap.uninstall_hook([site_dir])
        content = sitecustomize.read_bytes()
        assert original in content
        assert addition in content

    def test_discovery_returns_missing_user_site_for_creation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        missing_user_site = tmp_path / "missing-user-site"
        monkeypatch.setattr(
            bootstrap.site, "getusersitepackages", lambda: str(missing_user_site)
        )
        discovered = bootstrap.discover_site_packages()
        assert missing_user_site in discovered
        bootstrap.install_hook(discovered)
        assert (missing_user_site / "sitecustomize.py").is_file()

    def test_discovery_includes_user_site_and_active_venv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user_site = tmp_path / "user-site"
        venv_site = tmp_path / "venv-site"
        user_site.mkdir()
        venv_site.mkdir()
        monkeypatch.setattr(bootstrap.site, "getusersitepackages", lambda: str(user_site))
        monkeypatch.setattr(
            bootstrap.sysconfig, "get_paths", lambda: {"purelib": str(venv_site)}
        )
        monkeypatch.setattr(bootstrap.sys, "prefix", str(tmp_path / "venv"))
        monkeypatch.setattr(bootstrap.sys, "base_prefix", "/usr")

        discovered = bootstrap.discover_site_packages()
        assert user_site in discovered
        assert venv_site in discovered


class TestBootstrapGuardrails:
    def test_env_opt_out_alone_cannot_disable_hook(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # A rogue parent controls its child's environment, so an inherited
        # env var must never be sufficient to skip hook attachment.
        monkeypatch.setenv(bootstrap.DISABLE_ENV, "1")
        monkeypatch.setenv(bootstrap.DB_ENV, str(tmp_path / "audit.db"))
        monkeypatch.setattr(sys, "argv", [sys.executable, "-c", "pass"])
        monkeypatch.setattr(
            bootstrap.sysconfig, "get_paths", lambda: {"scripts": str(tmp_path / "empty")}
        )
        with patch("blackwall.audit.manager.AuditHookManager") as manager_cls:
            bootstrap.bootstrap_audit_hook()
        manager_cls.assert_called_once()

    def test_pip_invocation_is_not_intercepted(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv(bootstrap.DISABLE_ENV, raising=False)
        monkeypatch.setenv(bootstrap.DB_ENV, str(tmp_path / "audit.db"))
        pip_entry = tmp_path / "pip3"
        pip_entry.write_text("# synthetic pip entry point\n")
        monkeypatch.setattr(sys, "argv", [str(pip_entry), "install", "some-package"])
        monkeypatch.setattr(
            bootstrap.sysconfig, "get_paths", lambda: {"scripts": str(tmp_path)}
        )
        with patch("blackwall.audit.manager.AuditHookManager") as manager_cls:
            bootstrap.bootstrap_audit_hook()
        manager_cls.assert_not_called()

    @pytest.mark.parametrize(
        "argv",
        [
            ["/tmp/pipfetch.py", "build"],
            [sys.executable, "payload.py", "build"],
            [sys.executable, "setup.py", "install"],
        ],
    )
    def test_argv_spoofing_does_not_disable_hook(
        self,
        argv: list[str],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.delenv(bootstrap.DISABLE_ENV, raising=False)
        monkeypatch.setenv(bootstrap.DB_ENV, str(tmp_path / "audit.db"))
        monkeypatch.setattr(sys, "argv", argv)
        monkeypatch.setattr(
            bootstrap.sysconfig,
            "get_paths",
            lambda: {"scripts": str(tmp_path / "empty-scripts")},
        )
        with patch("blackwall.audit.manager.AuditHookManager") as manager_cls:
            bootstrap.bootstrap_audit_hook()
        manager_cls.assert_called_once()

    def test_genuine_python_m_pip_is_exempt(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv(bootstrap.DISABLE_ENV, raising=False)
        monkeypatch.setenv(bootstrap.DB_ENV, str(tmp_path / "audit.db"))
        monkeypatch.setattr(sys, "argv", [sys.executable, "-m", "pip", "install", "pkg"])
        with patch("blackwall.audit.manager.AuditHookManager") as manager_cls:
            bootstrap.bootstrap_audit_hook()
        manager_cls.assert_not_called()

    def test_genuine_pip_entrypoint_is_exempt(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        pip_entry = tmp_path / "pip3"
        pip_entry.write_text("# synthetic pip entry point\n")
        monkeypatch.delenv(bootstrap.DISABLE_ENV, raising=False)
        monkeypatch.setenv(bootstrap.DB_ENV, str(tmp_path / "audit.db"))
        monkeypatch.setattr(sys, "argv", [str(pip_entry), "install", "pkg"])
        monkeypatch.setattr(
            bootstrap.sysconfig, "get_paths", lambda: {"scripts": str(tmp_path)}
        )
        with patch("blackwall.audit.manager.AuditHookManager") as manager_cls:
            bootstrap.bootstrap_audit_hook()
        manager_cls.assert_not_called()

    def test_genuine_blackwall_service_command_is_exempt(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        entry = tmp_path / "blackwall"
        entry.write_text("# synthetic CLI entry point\n")
        monkeypatch.delenv(bootstrap.DISABLE_ENV, raising=False)
        monkeypatch.setenv(bootstrap.DB_ENV, str(tmp_path / "audit.db"))
        monkeypatch.setattr(sys, "argv", [str(entry), "service", "start"])
        monkeypatch.setattr(
            bootstrap.sysconfig, "get_paths", lambda: {"scripts": str(tmp_path)}
        )
        with patch("blackwall.audit.manager.AuditHookManager") as manager_cls:
            bootstrap.bootstrap_audit_hook()
        manager_cls.assert_not_called()

    def test_db_initialization_failure_is_fail_closed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv(bootstrap.DISABLE_ENV, raising=False)
        monkeypatch.setenv(bootstrap.DB_ENV, str(tmp_path / "audit.db"))
        monkeypatch.setattr(sys, "argv", [sys.executable, "-c", "pass"])
        with (
            patch("blackwall.audit.manager.AuditHookManager") as manager_cls,
            patch.object(bootstrap.os, "_exit", side_effect=SystemExit(1)) as exit_mock,
        ):
            manager_cls.return_value._get_conn.side_effect = OSError("corrupt database")
            with pytest.raises(SystemExit):
                bootstrap.bootstrap_audit_hook()
        exit_mock.assert_called_once_with(1)

    def test_corrupt_db_is_quarantined_and_recreated(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "audit.db"
        db_path.write_bytes(b"corrupt")
        monkeypatch.delenv(bootstrap.DISABLE_ENV, raising=False)
        monkeypatch.setenv(bootstrap.DB_ENV, str(db_path))
        monkeypatch.setattr(sys, "argv", [sys.executable, "-c", "pass"])
        bad_manager = MagicMock()
        bad_manager._get_conn.side_effect = OSError("corrupt database")
        good_manager = MagicMock()
        with (
            patch("blackwall.audit.manager.AuditHookManager", side_effect=[bad_manager, good_manager]),
            patch.object(bootstrap.os, "_exit") as exit_mock,
        ):
            bootstrap.bootstrap_audit_hook()
        exit_mock.assert_not_called()
        good_manager.start.assert_called_once_with()
        assert not db_path.exists() or db_path.stat().st_size == 0
        assert any("corrupt" in item.name for item in tmp_path.iterdir())

    def test_default_db_path_follows_current_home(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv(bootstrap.DISABLE_ENV, raising=False)
        monkeypatch.delenv(bootstrap.DB_ENV, raising=False)
        monkeypatch.setattr(sys, "argv", [sys.executable, "-c", "pass"])
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        with patch("blackwall.audit.manager.AuditHookManager") as manager_cls:
            bootstrap.bootstrap_audit_hook()
        manager_cls.assert_called_once_with(
            db_path=str(tmp_path / ".blackwall" / "audit.db")
        )

    def test_bootstrap_initializes_db_before_attaching(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv(bootstrap.DISABLE_ENV, raising=False)
        monkeypatch.setenv(bootstrap.DB_ENV, str(tmp_path / "audit.db"))
        monkeypatch.setattr(sys, "argv", [sys.executable, "-c", "pass"])
        with patch("blackwall.audit.manager.AuditHookManager") as manager_cls:
            bootstrap.bootstrap_audit_hook()
        manager_cls.assert_called_once_with(db_path=str(tmp_path / "audit.db"))
        manager_cls.return_value._get_conn.assert_called_once_with()
        manager_cls.return_value.start.assert_called_once_with()


class TestHookCLI:
    def test_install_and_status_report_injected_bootstrap(
        self, site_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(bootstrap, "discover_site_packages", lambda: [site_dir])
        runner = CliRunner()
        installed = runner.invoke(cli, ["hook", "install"])
        assert installed.exit_code == 0, installed.output
        assert (site_dir / "sitecustomize.py").exists()

        status = runner.invoke(cli, ["hook", "status"])
        assert status.exit_code == 0, status.output
        assert "installed" in status.output.lower()

    def test_uninstall_removes_bootstrap(
        self, site_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(bootstrap, "discover_site_packages", lambda: [site_dir])
        runner = CliRunner()
        assert runner.invoke(cli, ["hook", "install"]).exit_code == 0
        result = runner.invoke(cli, ["hook", "uninstall"])
        assert result.exit_code == 0, result.output
        assert not (site_dir / "sitecustomize.py").exists()


class TestCleanSubprocessBootstrap:
    @pytest.fixture()
    def bootstrapped_env(self, tmp_path: Path) -> dict[str, str]:
        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        bootstrap.install_hook([site_dir])
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join([str(REPO_SRC), str(site_dir)])
        env[bootstrap.DB_ENV] = str(tmp_path / "audit.db")
        env.pop(bootstrap.DISABLE_ENV, None)
        return env

    def test_clean_subprocess_auto_attaches_hook(
        self, bootstrapped_env: dict[str, str]
    ) -> None:
        code = (
            "from blackwall.audit import manager; "
            "print('ACTIVE' if getattr(manager, '_hook_registered', False) else 'INACTIVE')"
        )
        result = _child(code, bootstrapped_env)
        assert result.returncode == 0, result.stderr
        assert "ACTIVE" in result.stdout

    def test_child_recovers_from_unusable_db(
        self, bootstrapped_env: dict[str, str], tmp_path: Path
    ) -> None:
        broken_env = dict(bootstrapped_env)
        broken_env[bootstrap.DB_ENV] = str(tmp_path / "a-directory")
        (tmp_path / "a-directory").mkdir()
        result = _child(
            "from blackwall.audit import manager; "
            "print('ACTIVE' if getattr(manager, '_hook_registered', False) else 'INACTIVE')",
            broken_env,
        )
        assert result.returncode == 0, result.stderr
        assert "ACTIVE" in result.stdout

    def test_critical_bootstrap_files_are_write_protected(
        self, bootstrapped_env: dict[str, str], tmp_path: Path
    ) -> None:
        target = tmp_path / "site-packages" / "sitecustomize.py"
        env = dict(bootstrapped_env)
        env["BW_TEST_TARGET"] = str(target)
        code = (
            "import os\n"
            "target = os.environ['BW_TEST_TARGET']\n"
            "try:\n"
            "    with open(target, 'w') as handle: handle.write('stripped')\n"
            "except PermissionError:\n"
            "    print('BLOCKED')\n"
            "else:\n"
            "    print('ALLOWED')\n"
        )
        result = _child(code, env)
        assert result.returncode == 0, result.stderr
        assert "BLOCKED" in result.stdout, (result.stdout, result.stderr)
        assert target.read_text() != "stripped"

    def test_clean_subprocess_blocks_malicious_popen(
        self, bootstrapped_env: dict[str, str]
    ) -> None:
        code = (
            "import subprocess\n"
            "try:\n"
            "    subprocess.Popen(['/bin/echo', 'pwned'])\n"
            "except PermissionError:\n"
            "    print('BLOCKED')\n"
            "else:\n"
            "    print('ALLOWED')\n"
        )
        result = _child(code, bootstrapped_env)
        assert result.returncode == 0, result.stderr
        assert "BLOCKED" in result.stdout, (result.stdout, result.stderr)

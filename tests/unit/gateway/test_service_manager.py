"""Unit tests for the macOS LaunchAgent service manager (TASK-F01).

Covers the FR-10 contract:
- Valid XML plist with foreground supervision / throttling.
- Absolute-path (non-tilde) resolution at install time.
- ADC fallback and GCP fail-fast guards.
- Protected TypeSafe secret isolation in a 0600 dotenv file.
- launchctl dispatch for start/stop/status/uninstall and configure updates.
"""

from __future__ import annotations

import plistlib
import shlex
import stat
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from blackwall.cli import cli
from blackwall.gateway import service as svc

SECRET = "TS_SYNTHETIC_KEY_FOR_TESTS_0123456789"


@pytest.fixture()
def fake_home(tmp_path: Path) -> Path:
    """Isolated macOS-like home with a standard gcloud ADC file."""
    home = tmp_path / "home"
    adc_dir = home / ".config" / "gcloud"
    adc_dir.mkdir(parents=True)
    (adc_dir / "application_default_credentials.json").write_text(
        '{"type": "authorized_user", "refresh_token": "synthetic"}'
    )
    return home


def _clean_env(**overrides: str) -> dict[str, str]:
    env = {
        "HOME": "",
        "GCP_PROJECT": "",
        "GOOGLE_CLOUD_PROJECT": "",
        "GOOGLE_APPLICATION_CREDENTIALS": "",
        "TYPESAFE_API_KEY": "",
        "BW_SKIP_GCP_CHECK": "",
    }
    env.update(overrides)
    return env


class TestLaunchAgentPlistGeneration:
    def test_plist_is_valid_xml_with_foreground_supervision(self, fake_home: Path) -> None:
        config = svc.build_service_config(
            home=fake_home,
            env={"GCP_PROJECT": "blackwall-prod", "PATH": "/usr/bin:/bin"},
        )
        data = plistlib.loads(svc.generate_plist(config).encode("utf-8"))

        assert data["Label"] == svc.SERVICE_LABEL
        assert data["RunAtLoad"] is True
        assert data["KeepAlive"] == {"SuccessfulExit": False}
        assert data["ThrottleInterval"] == 30

        args = data["ProgramArguments"]
        assert "--foreground" in args
        assert "--transport" in args and args[args.index("--transport") + 1] == "http"
        assert "--port" in args and args[args.index("--port") + 1] == "9229"
        for flag in ("--config", "--pidfile", "--logfile", "--db"):
            assert args[args.index(flag) + 1].startswith("/")
        assert data["StandardOutPath"].startswith("/")
        assert data["StandardErrorPath"].startswith("/")

    def test_generated_plist_contains_no_unexpanded_tilde(self, fake_home: Path) -> None:
        config = svc.build_service_config(
            config="~/config/gateway.yaml",
            logfile="~/logs/blackwall.log",
            db="~/state/threats.db",
            pidfile="~/run/blackwall.pid",
            home=fake_home,
            env={"GCP_PROJECT": "blackwall-prod", "PATH": "/usr/bin"},
        )
        assert "~" not in svc.generate_plist(config)

    def test_environment_variables_include_gcp_paths_and_adc_fallback(
        self, fake_home: Path
    ) -> None:
        config = svc.build_service_config(
            home=fake_home,
            env={"GCP_PROJECT": "blackwall-prod", "PATH": "/usr/bin:/bin:/usr/sbin"},
        )
        env_vars = plistlib.loads(svc.generate_plist(config).encode("utf-8"))[
            "EnvironmentVariables"
        ]
        assert env_vars["GCP_PROJECT"] == "blackwall-prod"
        assert env_vars["GOOGLE_CLOUD_PROJECT"] == "blackwall-prod"
        assert env_vars["GEMINI_TIER"] == "paid"
        assert env_vars["PATH"] == "/usr/bin:/bin:/usr/sbin"
        assert env_vars["GOOGLE_APPLICATION_CREDENTIALS"] == str(
            (fake_home / ".config" / "gcloud" / "application_default_credentials.json").resolve()
        )
        assert "TYPESAFE_API_KEY" not in env_vars

    def test_explicit_credential_path_is_resolved_into_plist(self, fake_home: Path) -> None:
        creds = fake_home / "custom_creds.json"
        creds.write_text("{}")
        config = svc.build_service_config(
            home=fake_home,
            env={
                "GCP_PROJECT": "blackwall-prod",
                "GOOGLE_APPLICATION_CREDENTIALS": str(creds),
            },
        )
        env_vars = plistlib.loads(svc.generate_plist(config).encode("utf-8"))[
            "EnvironmentVariables"
        ]
        assert env_vars["GOOGLE_APPLICATION_CREDENTIALS"] == str(creds.resolve())

    def test_wrap_command_is_forwarded_to_upstream(self, fake_home: Path) -> None:
        config = svc.build_service_config(
            wrap="some-mcp-server --stdio",
            home=fake_home,
            env={"GCP_PROJECT": "blackwall-prod"},
        )
        args = plistlib.loads(svc.generate_plist(config).encode("utf-8"))["ProgramArguments"]
        assert "--wrap" in args
        assert shlex.split(args[args.index("--wrap") + 1]) == ["some-mcp-server", "--stdio"]

    def test_wrap_command_paths_are_resolved_at_install_time(
        self, tmp_path: Path, fake_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "server.py").write_text("# synthetic upstream\n")
        config = svc.build_service_config(
            wrap="./server.py --stdio",
            home=fake_home,
            env={"GCP_PROJECT": "blackwall-prod"},
        )
        data = plistlib.loads(svc.generate_plist(config).encode("utf-8"))
        args = data["ProgramArguments"]
        wrap_parts = shlex.split(args[args.index("--wrap") + 1])
        assert wrap_parts[0] == str((tmp_path / "server.py").resolve())
        assert wrap_parts[1:] == ["--stdio"]
        assert data["WorkingDirectory"] == str(tmp_path.resolve())

    def test_wrap_bare_command_is_resolved_via_path(self, fake_home: Path) -> None:
        with patch(
            "blackwall.gateway.service.shutil.which", return_value="/usr/local/bin/npx"
        ):
            config = svc.build_service_config(
                wrap="npx -y some-mcp-server --stdio",
                home=fake_home,
                env={"GCP_PROJECT": "blackwall-prod"},
            )
            args = plistlib.loads(svc.generate_plist(config).encode("utf-8"))[
                "ProgramArguments"
            ]
        assert shlex.split(args[args.index("--wrap") + 1]) == [
            "/usr/local/bin/npx",
            "-y",
            "some-mcp-server",
            "--stdio",
        ]

    def test_wrap_venv_python_symlink_is_preserved(
        self, tmp_path: Path, fake_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A venv interpreter symlink must not be dereferenced (Greptile P1)."""
        monkeypatch.chdir(tmp_path)
        venv_bin = tmp_path / ".venv" / "bin"
        venv_bin.mkdir(parents=True)
        (tmp_path / "base_python").write_text("# synthetic base interpreter\n")
        venv_python = venv_bin / "python"
        venv_python.symlink_to(tmp_path / "base_python")
        (tmp_path / "server.py").write_text("# synthetic upstream\n")

        config = svc.build_service_config(
            wrap="./.venv/bin/python server.py",
            home=fake_home,
            env={"GCP_PROJECT": "blackwall-prod"},
        )
        args = plistlib.loads(svc.generate_plist(config).encode("utf-8"))["ProgramArguments"]
        wrap_parts = shlex.split(args[args.index("--wrap") + 1])
        assert wrap_parts[0] == str(venv_python)
        # Bare relative args stay relative to the preserved install cwd.
        assert wrap_parts[1] == "server.py"
        assert plistlib.loads(svc.generate_plist(config).encode("utf-8"))[
            "WorkingDirectory"
        ] == str(tmp_path.resolve())

    def test_path_entries_with_tilde_are_expanded(self, fake_home: Path) -> None:
        config = svc.build_service_config(
            home=fake_home,
            env={"GCP_PROJECT": "blackwall-prod", "PATH": "~/bin:/usr/bin:/bin"},
        )
        xml = svc.generate_plist(config)
        assert "~" not in xml
        env_vars = plistlib.loads(xml.encode("utf-8"))["EnvironmentVariables"]
        assert env_vars["PATH"] == f"{fake_home.resolve()}/bin:/usr/bin:/bin"

    def test_missing_project_fails_fast(self, fake_home: Path) -> None:
        with pytest.raises(svc.ServiceError, match="GCP_PROJECT"):
            svc.build_service_config(home=fake_home, env={})

    def test_missing_adc_fails_fast(self, tmp_path: Path) -> None:
        empty_home = tmp_path / "no-adc"
        empty_home.mkdir()
        with pytest.raises(svc.ServiceError, match="ADC|application_default_credentials"):
            svc.build_service_config(
                home=empty_home, env={"GCP_PROJECT": "blackwall-prod"}
            )


class TestServiceCLI:
    def test_install_writes_launchagent_plist_to_platform_path(self, fake_home: Path) -> None:
        result = CliRunner().invoke(
            cli,
            ["service", "install"],
            env=_clean_env(HOME=str(fake_home), GCP_PROJECT="blackwall-prod"),
        )
        assert result.exit_code == 0, result.output
        plist_file = fake_home / "Library" / "LaunchAgents" / "com.blackwall.gateway.plist"
        assert plist_file.exists()
        assert plistlib.loads(plist_file.read_bytes())["Label"] == svc.SERVICE_LABEL

    def test_install_rejects_missing_project_with_nonzero_exit(self, fake_home: Path) -> None:
        result = CliRunner().invoke(
            cli, ["service", "install"], env=_clean_env(HOME=str(fake_home))
        )
        assert result.exit_code != 0
        assert "GCP_PROJECT" in result.output
        assert not (
            fake_home / "Library" / "LaunchAgents" / "com.blackwall.gateway.plist"
        ).exists()

    def test_install_persists_typesafe_key_only_in_0600_env_file(
        self, fake_home: Path
    ) -> None:
        result = CliRunner().invoke(
            cli,
            ["service", "install"],
            env=_clean_env(
                HOME=str(fake_home),
                GCP_PROJECT="blackwall-prod",
                TYPESAFE_API_KEY=SECRET,
            ),
        )
        assert result.exit_code == 0, result.output
        plist_file = fake_home / "Library" / "LaunchAgents" / "com.blackwall.gateway.plist"
        env_file = fake_home / ".blackwall" / "gateway.env"
        assert SECRET not in plist_file.read_text()
        assert SECRET not in result.output
        assert env_file.exists()
        assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
        assert f"TYPESAFE_API_KEY={SECRET}" in env_file.read_text()

    def test_configure_updates_project_and_credential_paths(self, fake_home: Path) -> None:
        runner = CliRunner()
        base_env = _clean_env(HOME=str(fake_home), GCP_PROJECT="blackwall-prod")
        assert runner.invoke(cli, ["service", "install"], env=base_env).exit_code == 0
        creds = fake_home / "rotated_creds.json"
        creds.write_text("{}")

        result = runner.invoke(
            cli,
            [
                "service",
                "configure",
                "--project",
                "rotated-project",
                "--credentials",
                str(creds),
            ],
            env=base_env,
        )
        assert result.exit_code == 0, result.output
        env_vars = plistlib.loads(
            (fake_home / "Library" / "LaunchAgents" / "com.blackwall.gateway.plist").read_bytes()
        )["EnvironmentVariables"]
        assert env_vars["GCP_PROJECT"] == "rotated-project"
        assert env_vars["GOOGLE_CLOUD_PROJECT"] == "rotated-project"
        assert env_vars["GOOGLE_APPLICATION_CREDENTIALS"] == str(creds.resolve())

    def test_configure_typesafe_key_uses_same_protected_file_rules(
        self, fake_home: Path
    ) -> None:
        runner = CliRunner()
        base_env = _clean_env(HOME=str(fake_home), GCP_PROJECT="blackwall-prod")
        assert runner.invoke(cli, ["service", "install"], env=base_env).exit_code == 0

        result = runner.invoke(
            cli,
            ["service", "configure", "--typesafe-key", SECRET],
            env=base_env,
        )
        assert result.exit_code == 0, result.output
        plist_file = fake_home / "Library" / "LaunchAgents" / "com.blackwall.gateway.plist"
        env_file = fake_home / ".blackwall" / "gateway.env"
        assert SECRET not in plist_file.read_text()
        assert SECRET not in result.output
        assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
        assert f"TYPESAFE_API_KEY={SECRET}" in env_file.read_text()

    def test_install_creates_parent_directories_for_log_and_pid(
        self, fake_home: Path
    ) -> None:
        nested_log = fake_home / "deep" / "logs" / "blackwall.log"
        nested_pid = fake_home / "run" / "blackwall.pid"
        result = CliRunner().invoke(
            cli,
            [
                "service",
                "install",
                "--logfile",
                str(nested_log),
                "--pidfile",
                str(nested_pid),
            ],
            env=_clean_env(HOME=str(fake_home), GCP_PROJECT="blackwall-prod"),
        )
        assert result.exit_code == 0, result.output
        assert nested_log.parent.is_dir()
        assert nested_pid.parent.is_dir()

    def test_uninstall_tolerates_already_unloaded_job(self, fake_home: Path) -> None:
        runner = CliRunner()
        base_env = _clean_env(HOME=str(fake_home), GCP_PROJECT="blackwall-prod")
        assert runner.invoke(cli, ["service", "install"], env=base_env).exit_code == 0
        plist_file = fake_home / "Library" / "LaunchAgents" / "com.blackwall.gateway.plist"
        with patch(
            "blackwall.gateway.service.subprocess.run",
            return_value=subprocess.CompletedProcess(
                [], 1, "", "Could not find specified service"
            ),
        ):
            result = runner.invoke(cli, ["service", "uninstall"], env=base_env)
        assert result.exit_code == 0, result.output
        assert not plist_file.exists()

    def test_uninstall_surfaces_unrelated_bootout_failure(self, fake_home: Path) -> None:
        runner = CliRunner()
        base_env = _clean_env(HOME=str(fake_home), GCP_PROJECT="blackwall-prod")
        assert runner.invoke(cli, ["service", "install"], env=base_env).exit_code == 0
        plist_file = fake_home / "Library" / "LaunchAgents" / "com.blackwall.gateway.plist"
        with patch(
            "blackwall.gateway.service.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, "", "permission denied"),
        ):
            result = runner.invoke(cli, ["service", "uninstall"], env=base_env)
        assert result.exit_code != 0
        assert "permission denied" in result.output
        assert plist_file.exists()

    def test_uninstall_bootouts_and_removes_plist(self, fake_home: Path) -> None:
        runner = CliRunner()
        base_env = _clean_env(HOME=str(fake_home), GCP_PROJECT="blackwall-prod")
        assert runner.invoke(cli, ["service", "install"], env=base_env).exit_code == 0
        plist_file = fake_home / "Library" / "LaunchAgents" / "com.blackwall.gateway.plist"

        with patch(
            "blackwall.gateway.service.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ) as run:
            result = runner.invoke(cli, ["service", "uninstall"], env=base_env)
        assert result.exit_code == 0, result.output
        assert not plist_file.exists()
        assert any("bootout" in str(call.args) for call in run.call_args_list)

    @pytest.mark.parametrize(
        ("command", "launchctl_verb"),
        [("start", "bootstrap"), ("stop", "bootout"), ("status", "list")],
    )
    def test_start_stop_status_dispatch_to_launchctl(
        self, fake_home: Path, command: str, launchctl_verb: str
    ) -> None:
        runner = CliRunner()
        base_env = _clean_env(HOME=str(fake_home), GCP_PROJECT="blackwall-prod")
        assert runner.invoke(cli, ["service", "install"], env=base_env).exit_code == 0
        with patch(
            "blackwall.gateway.service.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, "ok", ""),
        ) as run:
            result = runner.invoke(cli, ["service", command], env=base_env)
        assert result.exit_code == 0, result.output
        assert any(launchctl_verb in str(call.args) for call in run.call_args_list)


class TestDaemonStartupEnvLoad:
    def test_serve_loads_protected_env_file_at_startup(self, fake_home: Path, tmp_path: Path) -> None:
        with (
            patch("blackwall.cli.load_protected_env", return_value=True) as load_env,
            patch("blackwall.cli._run_gateway", new_callable=AsyncMock),
        ):
            result = CliRunner().invoke(
                cli,
                [
                    "serve",
                    "--skip-gcp-check",
                    "--foreground",
                    "--pidfile",
                    str(tmp_path / "blackwall.pid"),
                ],
                env=_clean_env(HOME=str(fake_home)),
            )
        assert result.exit_code == 0, result.output
        load_env.assert_called_once()

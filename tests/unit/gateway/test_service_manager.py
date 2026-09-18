"""Unit tests for Cross-Platform Service Manager (TASK-F01).

Validates TASK-F01 AC1-AC11:
- macOS plist XML generation + Linux systemd INI syntax/sectioning
- Absolute path resolution with zero unexpanded tildes
- Non-root system identity derivation (--user > SUDO_USER > blackwall)
- ADC fallback resolution from service-user home
- Platform path detection, upstream + GCP embedding
- Install fail-fast on missing GCP_PROJECT, supervision/throttling guards
- Uninstall cleanup, configure 0600 provisioning
"""

from __future__ import annotations

import os
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from click.testing import CliRunner

from blackwall.gateway import service as svc


def _test_env(tmp_path: Path, project: str = "BW_SYNTHETIC_MOCK_PROJECT_0192") -> dict[str, str]:
    adc = tmp_path / "adc.json"
    adc.write_text('{"client_id": "BW_SYNTHETIC_MOCK_CLIENT_0192"}', encoding="utf-8")
    return {
        "GCP_PROJECT": project,
        "GOOGLE_APPLICATION_CREDENTIALS": str(adc),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GEMINI_TIER": "paid",
    }


class TestPlatformDetection:
    def test_detect_darwin_and_linux(self) -> None:
        assert svc.detect_platform("Darwin") == "darwin"
        assert svc.detect_platform("darwin") == "darwin"
        assert svc.detect_platform("Linux") == "linux"

    def test_detect_windows_unsupported(self) -> None:
        with pytest.raises(RuntimeError):
            svc.detect_platform("Windows")

    def test_default_paths_per_platform(self, tmp_path: Path) -> None:
        plist = svc.get_user_plist_path(home=tmp_path)
        assert plist.name == "com.blackwall.gateway.plist"
        assert "LaunchAgents" in str(plist)
        user_unit = svc.get_user_systemd_path(home=tmp_path)
        assert user_unit.name == "blackwall.service"
        assert ".config/systemd/user" in str(user_unit)
        assert svc.get_system_systemd_path() == Path("/etc/systemd/system/blackwall.service")


class TestAbsolutePathResolution:
    def test_resolve_absolute_expands_user(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        resolved = svc.resolve_absolute("~/.blackwall/gateway.yaml")
        assert resolved.is_absolute()
        assert "~" not in str(resolved)

    def test_assert_no_tilde_rejects(self) -> None:
        with pytest.raises(ValueError):
            svc.assert_no_tilde("ExecStart=blackwall serve --config ~/.blackwall/x.yaml")
        svc.assert_no_tilde("/abs/path without marker")


class TestLaunchdPlistGeneration:
    def test_plist_xml_valid_with_supervision_and_env(self, tmp_path: Path) -> None:
        cfg = tmp_path / "gateway.yaml"
        cfg.write_text("upstream_servers: []\n", encoding="utf-8")
        pid = tmp_path / "blackwall.pid"
        log = tmp_path / "blackwall.log"
        db = tmp_path / "threat_signatures.db"
        env = _test_env(tmp_path)
        content = svc.generate_launchd_plist(
            config_path=str(cfg),
            pidfile_path=str(pid),
            logfile_path=str(log),
            db_path=str(db),
            wrap_cmd=None,
            env=env,
        )
        assert "~" not in content
        root = ET.fromstring(content)
        assert root.tag == "plist"
        text = content
        assert "com.blackwall.gateway" in text
        assert "serve" in text and "--foreground" in text
        assert "--config" in text and str(cfg) in text
        assert "RunAtLoad" in text
        assert "KeepAlive" in text and "SuccessfulExit" in text
        assert "<integer>30</integer>" in text  # ThrottleInterval=30
        for key in ("GCP_PROJECT", "GEMINI_TIER", "PATH"):
            assert key in text
        assert "--transport" in text and "http" in text
        assert "9229" in text

    def test_plist_embeds_wrap_upstream(self, tmp_path: Path) -> None:
        env = _test_env(tmp_path)
        content = svc.generate_launchd_plist(
            config_path=str(tmp_path / "gateway.yaml"),
            pidfile_path=str(tmp_path / "blackwall.pid"),
            logfile_path=str(tmp_path / "blackwall.log"),
            db_path=str(tmp_path / "threat_signatures.db"),
            wrap_cmd="python -m BW_SYNTHETIC_MOCK_SERVER_0192",
            env=env,
        )
        assert "--wrap" in content or "BW_SYNTHETIC_MOCK_SERVER_0192" in content

    def test_plist_install_fails_fast_without_gcp_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GCP_PROJECT", raising=False)
        monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
        with pytest.raises(ValueError):
            svc.install_service(
                config_path=None,
                wrap_cmd=None,
                project=None,
                credentials=None,
                system=False,
                user=None,
                platform_override="darwin",
                home=tmp_path,
                output_path=tmp_path / "out.plist",
            )


class TestSystemdUnitGeneration:
    def _env(self, tmp_path: Path) -> dict[str, str]:
        return _test_env(tmp_path)

    def test_systemd_sectioning_and_supervision_user_unit(self, tmp_path: Path) -> None:
        cfg = tmp_path / "gateway.yaml"
        cfg.write_text("upstream_servers: []\n", encoding="utf-8")
        env = self._env(tmp_path)
        content = svc.generate_systemd_unit(
            config_path=str(cfg),
            pidfile_path=str(tmp_path / "blackwall.pid"),
            logfile_path=str(tmp_path / "blackwall.log"),
            db_path=str(tmp_path / "threat_signatures.db"),
            wrap_cmd=None,
            env=env,
            system=False,
            user=None,
            group=None,
        )
        assert "~" not in content
        assert "[Unit]" in content and "[Service]" in content and "[Install]" in content
        unit_section = content.split("[Service]")[0]
        service_section = content.split("[Service]")[1]
        assert "StartLimitBurst=5" in unit_section
        assert "StartLimitIntervalSec=60s" in unit_section
        assert "StartLimitBurst" not in service_section
        assert "Type=exec" in service_section
        assert "MemoryMax=350M" in service_section
        assert "MemoryHigh=320M" in service_section
        assert "Restart=on-failure" in service_section
        assert "RestartSec=5s" in service_section
        assert "PIDFile=" in service_section
        assert "--foreground" in service_section
        assert "--pidfile" in service_section and "--logfile" in service_section
        assert "--db" in service_section
        assert "After=network.target" in unit_section

    def test_system_unit_fhs_non_root_and_directories(self, tmp_path: Path) -> None:
        adc = tmp_path / "adc.json"
        adc.write_text('{"client_id": "BW_SYNTHETIC_MOCK_CLIENT_0192"}', encoding="utf-8")
        env = {
            "GCP_PROJECT": "BW_SYNTHETIC_MOCK_PROJECT_0192",
            "GOOGLE_APPLICATION_CREDENTIALS": str(adc),
            "PATH": "/usr/bin:/bin",
            "GEMINI_TIER": "paid",
        }
        content = svc.generate_systemd_unit(
            config_path="/etc/blackwall/gateway.yaml",
            pidfile_path="/run/blackwall/blackwall.pid",
            logfile_path="/var/log/blackwall/blackwall.log",
            db_path="/var/lib/blackwall/threat_signatures.db",
            wrap_cmd=None,
            env=env,
            system=True,
            user="BW_SYNTHETIC_MOCK_USER_0192",
            group="BW_SYNTHETIC_MOCK_USER_0192",
        )
        assert "~" not in content
        assert "User=BW_SYNTHETIC_MOCK_USER_0192" in content
        assert "Group=BW_SYNTHETIC_MOCK_USER_0192" in content
        assert "User=root" not in content
        assert "RuntimeDirectory=blackwall" in content
        assert "StateDirectory=blackwall" in content
        assert "LogsDirectory=blackwall" in content
        assert "--pidfile /run/blackwall/blackwall.pid" in content
        assert "--logfile /var/log/blackwall/blackwall.log" in content
        assert "BLACKWALL_DB_PATH=/var/lib/blackwall/threat_signatures.db" in content

    def test_system_unit_rejects_root_user(self, tmp_path: Path) -> None:
        env = self._env(tmp_path)
        with pytest.raises(ValueError):
            svc.generate_systemd_unit(
                config_path="/etc/blackwall/gateway.yaml",
                pidfile_path="/run/blackwall/blackwall.pid",
                logfile_path="/var/log/blackwall/blackwall.log",
                db_path="/var/lib/blackwall/threat_signatures.db",
                wrap_cmd=None,
                env=env,
                system=True,
                user="root",
                group="root",
            )

    def test_derive_system_user_priority(self, monkeypatch: pytest.MonkeyPatch) -> None:
        user, _group = svc.derive_system_user(explicit_user="alice")
        assert user == "alice"
        monkeypatch.setenv("SUDO_USER", "bob")
        user2, _ = svc.derive_system_user(explicit_user=None)
        assert user2 == "bob"
        monkeypatch.delenv("SUDO_USER", raising=False)
        user3, group3 = svc.derive_system_user(explicit_user=None)
        assert user3 == "blackwall" and group3 == "blackwall"

    def test_adc_fallback_resolves_service_user_home(self, tmp_path: Path) -> None:
        service_home = tmp_path / "svcuser"
        adc_dir = service_home / ".config" / "gcloud"
        adc_dir.mkdir(parents=True)
        adc_file = adc_dir / "application_default_credentials.json"
        adc_file.write_text('{"client_id": "BW_SYNTHETIC_MOCK_CLIENT_0192"}', encoding="utf-8")
        resolved = svc.resolve_adc_path(explicit=None, service_home=service_home)
        assert resolved == adc_file.resolve()
        assert "~" not in str(resolved)


class TestInstallUninstallConfigure:
    def test_install_writes_correct_platform_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env = _test_env(tmp_path)
        for key, val in env.items():
            monkeypatch.setenv(key, val)
        out = tmp_path / "com.blackwall.gateway.plist"
        result = svc.install_service(
            config_path=None,
            wrap_cmd=None,
            project=None,
            credentials=None,
            system=False,
            user=None,
            platform_override="darwin",
            home=tmp_path,
            output_path=out,
        )
        assert result == out
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "~" not in content
        assert "GCP_PROJECT" in content

    def test_install_linux_user_unit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env = _test_env(tmp_path)
        for key, val in env.items():
            monkeypatch.setenv(key, val)
        out = tmp_path / "blackwall.service"
        result = svc.install_service(
            config_path=None,
            wrap_cmd=None,
            project=None,
            credentials=None,
            system=False,
            user=None,
            platform_override="linux",
            home=tmp_path,
            output_path=out,
        )
        assert result.exists()
        assert "~" not in result.read_text(encoding="utf-8")

    def test_uninstall_removes_file_and_unloads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import patch

        target = tmp_path / "blackwall.service"
        target.write_text("dummy", encoding="utf-8")
        with patch("blackwall.gateway.service.subprocess.run") as mock_run:
            ok = svc.uninstall_service(
                system=False,
                platform_override="linux",
                home=tmp_path,
                output_path=target,
            )
        assert ok is True
        assert not target.exists()
        assert mock_run.called

    def test_configure_writes_env_and_credentials_0600(self, tmp_path: Path) -> None:
        src_creds = tmp_path / "src_adc.json"
        src_creds.write_text('{"client_id": "BW_SYNTHETIC_MOCK_CLIENT_0192"}', encoding="utf-8")
        env_file, cred_file = svc.configure_system_service(
            project="BW_SYNTHETIC_MOCK_PROJECT_0192",
            credentials_path=str(src_creds),
            etc_root=tmp_path,
        )
        assert env_file.exists() and cred_file.exists()
        mode = stat.S_IMODE(cred_file.stat().st_mode)
        assert mode == 0o600
        assert "BW_SYNTHETIC_MOCK_PROJECT_0192" in env_file.read_text(encoding="utf-8")


class TestServiceCLI:
    def test_service_status_runs(self) -> None:
        from blackwall.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["service", "status"])
        assert result.exit_code == 0

    def test_service_install_fails_fast_without_project(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from blackwall.cli import cli

        monkeypatch.delenv("GCP_PROJECT", raising=False)
        monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
        runner = CliRunner()
        result = runner.invoke(cli, ["service", "install"])
        assert result.exit_code != 0


class TestGreploopReviewFixes:
    def test_fallback_command_uses_module_invocation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(svc.shutil, "which", lambda _name: None)
        prefix = svc.build_service_command_prefix()
        assert prefix[0].endswith("python") or "python" in prefix[0]
        assert "-m" in prefix and "blackwall.cli" in prefix

    def test_systemd_execstart_quotes_wrap_command(self, tmp_path: Path) -> None:
        cfg = tmp_path / "gateway.yaml"
        cfg.write_text("upstream_servers: []\n", encoding="utf-8")
        env = _test_env(tmp_path)
        content = svc.generate_systemd_unit(
            str(cfg), str(tmp_path / "a.pid"), str(tmp_path / "a.log"),
            str(tmp_path / "a.db"), "python -m BW_SYNTHETIC_MOCK_SERVER_0192",
            env, system=False,
        )
        import shlex as _shlex

        exec_line = next(ln for ln in content.splitlines() if ln.startswith("ExecStart="))
        argv = _shlex.split(exec_line[len("ExecStart="):])
        assert "--wrap" in argv
        assert "python -m BW_SYNTHETIC_MOCK_SERVER_0192" in argv

    def test_system_unit_includes_environment_file(self, tmp_path: Path) -> None:
        env = _test_env(tmp_path)
        content = svc.generate_systemd_unit(
            "/etc/blackwall/gateway.yaml", "/run/blackwall/blackwall.pid",
            "/var/log/blackwall/blackwall.log", "/var/lib/blackwall/threat_signatures.db",
            None, env, system=True, user="svcuser", group="svcuser",
        )
        assert "EnvironmentFile=-/etc/default/blackwall" in content

    def test_ensure_system_user_provisions_dedicated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import pwd as _pwd

        monkeypatch.setattr(_pwd, "getpwnam", lambda _u: (_ for _ in ()).throw(KeyError(_u)))
        from unittest.mock import patch

        with patch("blackwall.gateway.service.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            svc.ensure_system_user("blackwall")
        assert mock_run.called
        invited = mock_run.call_args[0][0]
        assert "useradd" in invited and "/var/lib/blackwall" in invited

    def test_configure_user_service_persists_project_and_credentials(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        src.write_text('{"client_id": "BW_SYNTHETIC_MOCK_CLIENT_0192"}', encoding="utf-8")
        env_file, cred = svc.configure_user_service(
            project="BW_SYNTHETIC_MOCK_PROJECT_0192",
            credentials_path=str(src),
            home=tmp_path,
            platform_override="linux",
        )
        assert env_file is not None and env_file.exists()
        assert "BW_SYNTHETIC_MOCK_PROJECT_0192" in env_file.read_text(encoding="utf-8")
        assert cred is not None and cred.exists()
        assert stat.S_IMODE(cred.stat().st_mode) == 0o600

    def test_configure_user_service_accepts_credentials_only(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        src.write_text('{"client_id": "BW_SYNTHETIC_MOCK_CLIENT_0192"}', encoding="utf-8")
        env_file, cred = svc.configure_user_service(
            project=None, credentials_path=str(src),
            home=tmp_path, platform_override="linux",
        )
        assert env_file.exists() and cred is not None and cred.exists()

"""
Unit tests for CLI Entry Point and Daemon Lifecycle (TASK-C03).

Validates:
- blackwall version
- blackwall init (scaffolding ~/.blackwall/ with default configuration)
- blackwall serve startup guards (non-loopback requires auth token, missing GCP credentials fails fast)
- blackwall serve foreground mode creates and cleans up PID file
- blackwall stop sends SIGTERM, verifies termination, and cleans up PID file
- blackwall status reports daemon state and DB statistics
- Non-loopback valid-token happy path (Rule 45 testing matrix)
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import aiohttp
import pytest
from click.testing import CliRunner

from blackwall.cli import cli, validate_gcp_credentials
from blackwall.gateway.daemon import (
    is_process_alive,
    read_pid_file,
    write_pid_file,
)
from blackwall.gateway.server import MCPGatewayServer


class TestBlackwallCLI:
    """Tests for the Blackwall CLI commands."""

    def test_version_command(self) -> None:
        """'blackwall version' prints version string and exits 0."""
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "2.0.0" in result.output

    def test_init_command(self, tmp_path: Path) -> None:
        """'blackwall init --dir <path>' scaffolds directory with policy.yaml, gateway.yaml, threat_signatures.db."""
        runner = CliRunner()
        target_dir = tmp_path / "blackwall_home"
        result = runner.invoke(cli, ["init", "--dir", str(target_dir)])

        assert result.exit_code == 0
        assert target_dir.exists()
        assert (target_dir / "policy.yaml").exists()
        assert (target_dir / "gateway.yaml").exists()
        assert (target_dir / "threat_signatures.db").exists()
        assert "Initialized Blackwall configuration" in result.output

    def test_serve_startup_guard_fails_non_loopback_without_auth_token(self) -> None:
        """'blackwall serve --host 0.0.0.0' without auth token fails fast with clear error."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "serve",
                "--host",
                "0.0.0.0",
                "--skip-gcp-check",
                "--foreground",
            ],
            env={"BLACKWALL_AUTH_TOKEN": ""},
        )
        assert result.exit_code != 0
        assert "auth token" in result.output.lower() or "refusing to start" in result.output.lower()

    def test_serve_missing_gcp_credentials_fails_fast(self) -> None:
        """'blackwall serve' fails fast when GCP credentials/project are missing."""
        runner = CliRunner()
        # Clean environment without GCP credentials
        clean_env = {
            "GCP_PROJECT": "",
            "GOOGLE_CLOUD_PROJECT": "",
            "GOOGLE_APPLICATION_CREDENTIALS": "",
            "BW_SKIP_GCP_CHECK": "",
        }
        result = runner.invoke(
            cli,
            ["serve", "--foreground"],
            env=clean_env,
        )
        assert result.exit_code != 0
        assert "GCP" in result.output or "Application Default Credentials" in result.output

    def test_serve_foreground_creates_and_cleans_up_pidfile(self, tmp_path: Path) -> None:
        """'blackwall serve --foreground --pidfile' creates PID file upon start and deletes it upon termination."""
        pid_file = tmp_path / "test_foreground.pid"
        runner = CliRunner()

        async def _mock_run(**kwargs: Any) -> None:
            # While running in foreground, the pidfile MUST exist and contain the current process PID
            assert pid_file.exists()
            assert read_pid_file(pid_file) == os.getpid()

        with patch("blackwall.cli._run_gateway", side_effect=_mock_run):
            result = runner.invoke(
                cli,
                [
                    "serve",
                    "--foreground",
                    "--skip-gcp-check",
                    "--pidfile",
                    str(pid_file),
                ],
            )
            assert result.exit_code == 0

        # Upon termination, the pidfile MUST be removed
        assert not pid_file.exists()

    def test_validate_gcp_credentials_helper(self, tmp_path: Path) -> None:
        """Direct unit test of validate_gcp_credentials function."""
        # 1. Missing project
        with patch.dict(os.environ, {"GCP_PROJECT": "", "GOOGLE_CLOUD_PROJECT": "", "BW_SKIP_GCP_CHECK": ""}):
            valid, err = validate_gcp_credentials()
            assert valid is False
            assert "project" in err.lower()

        # 2. Project present, but no credentials
        fake_adc = tmp_path / "nonexistent.json"
        with patch.dict(
            os.environ,
            {
                "GCP_PROJECT": "test-proj",
                "GOOGLE_APPLICATION_CREDENTIALS": str(fake_adc),
                "BW_SKIP_GCP_CHECK": "",
            },
        ):
            valid, err = validate_gcp_credentials()
            assert valid is False
            assert "credentials" in err.lower()

        # 3. Valid credentials file
        fake_creds = tmp_path / "valid_creds.json"
        fake_creds.write_text('{"type": "service_account"}')
        with patch.dict(
            os.environ,
            {
                "GCP_PROJECT": "test-proj",
                "GOOGLE_APPLICATION_CREDENTIALS": str(fake_creds),
                "BW_SKIP_GCP_CHECK": "",
            },
        ):
            valid, err = validate_gcp_credentials()
            assert valid is True
            assert err == ""

        # 4. Bypass flag
        with patch.dict(os.environ, {"BW_SKIP_GCP_CHECK": "1"}):
            valid, err = validate_gcp_credentials()
            assert valid is True

    def test_stop_command_terminates_process_and_removes_pidfile(self, tmp_path: Path) -> None:
        """'blackwall stop' terminates running daemon and cleans up PID file."""
        pid_file = tmp_path / "blackwall.pid"

        # Start a dummy background process
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            write_pid_file(pid_file, proc.pid)
            assert is_process_alive(proc.pid) is True
            assert pid_file.exists()

            runner = CliRunner()
            result = runner.invoke(cli, ["stop", "--pidfile", str(pid_file)])

            assert result.exit_code == 0
            assert "stopped" in result.output.lower()

            # Process should be terminated
            proc.poll()
            assert proc.returncode is not None or not is_process_alive(proc.pid)
            assert not pid_file.exists()
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_stop_command_when_not_running(self, tmp_path: Path) -> None:
        """'blackwall stop' handles dead or nonexistent PID files gracefully."""
        pid_file = tmp_path / "nonexistent.pid"
        runner = CliRunner()
        result = runner.invoke(cli, ["stop", "--pidfile", str(pid_file)])
        assert result.exit_code == 0
        assert "not running" in result.output.lower()

    def test_status_command_stopped_and_running(self, tmp_path: Path) -> None:
        """'blackwall status' accurately reports stopped and running states."""
        pid_file = tmp_path / "blackwall.pid"
        runner = CliRunner()

        # 1. Stopped state
        result_stopped = runner.invoke(cli, ["status", "--pidfile", str(pid_file)])
        assert result_stopped.exit_code == 0
        assert "stopped" in result_stopped.output.lower()

        # 2. Running state
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            write_pid_file(pid_file, proc.pid)
            result_running = runner.invoke(cli, ["status", "--pidfile", str(pid_file)])
            assert result_running.exit_code == 0
            assert "running" in result_running.output.lower()
            assert str(proc.pid) in result_running.output
        finally:
            proc.kill()
            if pid_file.exists():
                pid_file.unlink()

    @pytest.mark.asyncio
    async def test_remote_binding_valid_token_happy_path(self) -> None:
        """
        Rule 45 matrix: Validates that non-loopback HTTP server started with a valid auth token
        accepts and processes authorized requests.
        """
        server = MCPGatewayServer(
            host="0.0.0.0",
            port=0,
            auth_token="valid-secret-token",
            allowed_hosts=["0.0.0.0", "localhost", "127.0.0.1"],
        )

        app = server.create_app()
        runner = aiohttp.web.AppRunner(app)
        await runner.setup()
        site = aiohttp.web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()

        sockets = site._server.sockets  # type: ignore[union-attr]
        port = sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/mcp"

        try:
            async with aiohttp.ClientSession() as session:
                # 1. Request with invalid token -> 401
                async with session.post(
                    url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    headers={"Authorization": "Bearer wrong-token", "Host": "localhost"},
                ) as resp_bad:
                    assert resp_bad.status == 401

                # 2. Request with valid token -> 200 OK
                async with session.post(
                    url,
                    json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
                    headers={"Authorization": "Bearer valid-secret-token", "Host": "localhost"},
                ) as resp_good:
                    assert resp_good.status == 200
                    body = await resp_good.json()
                    assert body["id"] == 2
        finally:
            await site.stop()
            await runner.cleanup()

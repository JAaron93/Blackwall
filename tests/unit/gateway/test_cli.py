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

import asyncio
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

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

        # 5. Ambient ADC via google.auth.default()
        mock_creds = MagicMock()
        with patch.dict(
            os.environ,
            {
                "GCP_PROJECT": "test-proj",
                "GOOGLE_APPLICATION_CREDENTIALS": "",
                "BW_SKIP_GCP_CHECK": "",
            },
        ), patch("pathlib.Path.home", return_value=tmp_path / "fake_home"), patch(
            "google.auth.default", return_value=(mock_creds, "test-proj")
        ):
            valid, err = validate_gcp_credentials()
            assert valid is True
            assert err == ""

    def test_stop_command_terminates_process_and_removes_pidfile(self, tmp_path: Path) -> None:
        """'blackwall stop' terminates running daemon and cleans up PID file."""
        pid_file = tmp_path / "blackwall.pid"

        # Start a dummy Blackwall background process in its own process group (Rule 10)
        proc = subprocess.Popen(
            [sys.executable, "-c", "# blackwall daemon\nimport time; time.sleep(60)"],
            preexec_fn=os.setsid,
        )
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
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            if proc.poll() is None:
                proc.kill()

    def test_stop_command_stale_pid_unrelated_process_does_not_kill(self, tmp_path: Path) -> None:
        """'blackwall stop' does not signal unrelated process on stale PID, removes PID file."""
        pid_file = tmp_path / "stale.pid"
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            preexec_fn=os.setsid,
        )
        try:
            write_pid_file(pid_file, proc.pid)
            assert is_process_alive(proc.pid) is True

            runner = CliRunner()
            result = runner.invoke(cli, ["stop", "--pidfile", str(pid_file)])

            assert result.exit_code == 0
            # Unrelated process must still be running
            assert is_process_alive(proc.pid) is True
            # Stale PID file must have been removed
            assert not pid_file.exists()
        finally:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
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

        # 2. Running state (Rule 10 process group cleanup)
        proc = subprocess.Popen(
            [sys.executable, "-c", "# blackwall daemon\nimport time; time.sleep(60)"],
            preexec_fn=os.setsid,
        )
        try:
            write_pid_file(pid_file, proc.pid)
            result_running = runner.invoke(cli, ["status", "--pidfile", str(pid_file)])
            assert result_running.exit_code == 0
            assert "running" in result_running.output.lower()
            assert str(proc.pid) in result_running.output
        finally:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            if proc.poll() is None:
                proc.kill()
            if pid_file.exists():
                pid_file.unlink()

    def test_status_command_with_threat_database_stats(self, tmp_path: Path) -> None:
        """'blackwall status' queries and reports threat graph stats and recent verdicts from DB."""
        import asyncio

        from blackwall.db.repository import SQLiteThreatRepository

        db_path = tmp_path / "test_threats.db"

        async def _seed_db() -> None:
            repo = SQLiteThreatRepository(db_path=str(db_path))
            try:
                await repo.initialize()
                await repo.writeSignature(
                    {
                        "signature_id": "sig-001",
                        "pattern": "malicious_eval",
                        "action": "BLOCK",
                        "severity": 0.9,
                    }
                )
                async with repo.pool.connection() as conn:
                    await conn.execute(
                        "INSERT INTO audit_incidents (incident_id, incident_type, timestamp, details) VALUES (?, ?, ?, ?)",
                        ("inc-123", "BLOCK", 1700000000, "Blocked suspicious execution"),
                    )
            finally:
                await repo.close()

        asyncio.run(_seed_db())

        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--db-path", str(db_path)])

        assert result.exit_code == 0
        assert "Total Signatures" in result.output
        assert "Recent Verdicts" in result.output
        assert "Yes" in result.output

    def test_status_command_corrupted_database_reports_inaccessible(self, tmp_path: Path) -> None:
        """'blackwall status' reports database as Inaccessible/Corrupted when DB file is invalid."""
        corrupt_db = tmp_path / "corrupt.db"
        corrupt_db.write_text("NOT A VALID SQLITE DATABASE FILE")

        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--db-path", str(corrupt_db)])

        assert result.exit_code == 0
        assert "Inaccessible/Corrupted" in result.output
        assert "DB Accessible" in result.output
        assert "DB Accessible  │ Yes" not in result.output

    def test_serve_stdio_transport_forces_foreground_and_does_not_daemonize(self) -> None:
        """'blackwall serve --transport stdio' must never call daemonize; stdio requires foreground."""
        runner = CliRunner()
        with patch("blackwall.cli.daemonize") as mock_daemonize, patch("blackwall.cli._run_gateway") as mock_run:
            async def _dummy_run(*args, **kwargs):
                return
            mock_run.side_effect = _dummy_run

            result = runner.invoke(
                cli,
                ["serve", "--transport", "stdio", "--skip-gcp-check"],
            )

            assert result.exit_code == 0
            mock_daemonize.assert_not_called()
            mock_run.assert_called_once()

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

    @pytest.mark.asyncio
    async def test_run_gateway_fails_fast_on_sync_resolver_error(self, tmp_path: Path) -> None:
        """P1: In _run_gateway, if SyncResolver fails to initialize, fail fast and do not fall back to resolver=None."""
        from blackwall.cli import _run_gateway

        db_path = tmp_path / "threats.db"

        with patch("google.genai.Client", side_effect=RuntimeError("Vertex auth failed")):
            with pytest.raises(RuntimeError, match="Failed to initialize SyncResolver"):
                await _run_gateway(
                    transport="http",
                    host="127.0.0.1",
                    port=9229,
                    auth_token=None,
                    upstream_mgr=None,
                    db_path=str(db_path),
                )

    def test_serve_command_passes_policy_to_run_gateway(self, tmp_path: Path) -> None:
        """P1: 'blackwall serve --policy <path>' passes policy_path into _run_gateway."""
        runner = CliRunner()
        policy_file = tmp_path / "custom_policy.yaml"
        policy_file.write_text("version: '1.0.0'\n")

        captured_kwargs: dict[str, Any] = {}

        async def _mock_run(**kwargs: Any) -> None:
            captured_kwargs.update(kwargs)

        with patch("blackwall.cli._run_gateway", side_effect=_mock_run):
            result = runner.invoke(
                cli,
                [
                    "serve",
                    "--foreground",
                    "--skip-gcp-check",
                    "--policy",
                    str(policy_file),
                ],
            )
            assert result.exit_code == 0
            assert captured_kwargs.get("policy_path") == str(policy_file)

    @pytest.mark.asyncio
    async def test_run_gateway_wires_policy_into_sync_resolver(self, tmp_path: Path) -> None:
        """P1: _run_gateway loads policy.yaml into HybridPolicyServer and passes it to SyncResolver."""
        from blackwall.cli import _run_gateway
        from blackwall.policy.engine import StructuralGatingEngine
        from blackwall.sync_resolver import SyncResolver

        db_path = tmp_path / "threats.db"
        policy_file = tmp_path / "policy.yaml"

        # Write valid minimal policy configuration
        from blackwall.cli import DEFAULT_POLICY_YAML
        policy_file.write_text(DEFAULT_POLICY_YAML)

        mock_client = MagicMock()
        mock_resolver = MagicMock()

        with patch("google.genai.Client", return_value=mock_client), \
             patch("blackwall.sync_resolver.SyncResolver", return_value=mock_resolver) as mock_sync_cls, \
             patch("blackwall.gateway.server.MCPGatewayServer.start_http", return_value=None), \
             patch("blackwall.gateway.server.MCPGatewayServer.stop", return_value=None):

            # Use a task that we cancel after server init to terminate _run_gateway
            async def _run_with_timeout():
                task = asyncio.create_task(
                    _run_gateway(
                        transport="http",
                        host="127.0.0.1",
                        port=9229,
                        auth_token=None,
                        upstream_mgr=None,
                        db_path=str(db_path),
                        policy_path=str(policy_file),
                    )
                )
                await asyncio.sleep(0.05)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            await _run_with_timeout()

            # Verify SyncResolver was instantiated with policy_server wired
            mock_sync_cls.assert_called_once()
            call_kwargs = mock_sync_cls.call_args.kwargs
            assert "policy_server" in call_kwargs
            policy_server = call_kwargs["policy_server"]
            assert policy_server is not None
            assert hasattr(policy_server, "structural_engine")
            assert isinstance(policy_server.structural_engine, StructuralGatingEngine)

    @pytest.mark.asyncio
    async def test_run_gateway_explicit_nonexistent_policy_raises(self, tmp_path: Path) -> None:
        """P1: An explicitly specified nonexistent policy file raises FileNotFoundError."""
        from blackwall.cli import _run_gateway

        db_path = tmp_path / "threats.db"
        nonexistent = tmp_path / "missing_policy.yaml"

        with pytest.raises(FileNotFoundError, match="Policy file not found"):
            await _run_gateway(
                transport="http",
                host="127.0.0.1",
                port=9229,
                auth_token=None,
                upstream_mgr=None,
                db_path=str(db_path),
                policy_path=str(nonexistent),
            )

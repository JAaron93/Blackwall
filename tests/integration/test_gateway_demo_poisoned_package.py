"""Integration test for TASK-G04 The Poisoned Package (TDD — written first).

OWASP LLM05 — Supply Chain Vulnerabilities (https://genai.owasp.org/) /
MITRE ATLAS AML.T0049 — Exploit ML Supply Chain
(https://atlas.mitre.org/techniques/AML.T0049)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


class TestGatewayDemoPoisonedPackage:
    def test_poisoned_package_allows_pip_and_blocks_runtime_escapes(
        self, tmp_path: Path
    ) -> None:
        from blackwall.audit import manager as audit_manager_mod
        from scripts.gateway_demo.scenario_poisoned_package import run_poisoned_package

        before_hook_registered = audit_manager_mod._hook_registered
        before_active_managers = list(audit_manager_mod._active_managers)

        result = run_poisoned_package(tmp_path)
        assert result["transport"] == "in-process"
        assert result["receiver_active"] is False
        assert result["exfil_post_count"] is None

        # 1. Protocol layer ALLOWs legitimate package install run_command.
        run_cmd = result["run_command_response"]
        assert "error" not in run_cmd
        assert run_cmd["id"] == "poisoned-pkg-install-1"
        assert run_cmd["result"]["echoedTool"] == "run_command"
        assert "pip install" in run_cmd["result"]["echoedArguments"]["command"]

        # 2. Runtime audit hook in isolated child subprocess intercepts all 3 vectors.
        assert result["intercepted"] == [
            "subprocess.Popen",
            "os.system",
            "socket.connect",
        ]
        assert result["audit_incident_count"] >= 3
        assert {
            "SUBPROCESS_EXECUTION",
            "SYSTEM_COMMAND_INJECTION",
            "MALICIOUS_IOC_CONNECTION",
        }.issubset(set(result["audit_incident_types"]))

        # 3. Structured JSON event log captures ALLOW at gateway + BLOCK at audit hook.
        results_path = Path(result["results_path"])
        assert results_path.parent == tmp_path
        assert results_path.exists()
        logged = json.loads(results_path.read_text(encoding="utf-8"))
        assert logged["scenario"] == "poisoned_package"
        assert logged["taxonomy"]["owasp"] == "LLM05"
        assert logged["taxonomy"]["mitre"] == "AML.T0049"

        events = logged["events"]
        assert events[0]["layer"] == "mcp_gateway"
        assert events[0]["verdict"] == "ALLOW"
        assert events[0]["tool"] == "run_command"
        runtime_blocks = [
            e for e in events if e.get("layer") == "python_audit_hook"
        ]
        assert [e["verdict"] for e in runtime_blocks] == ["BLOCK", "BLOCK", "BLOCK"]
        assert [e["vector"] for e in runtime_blocks] == [
            "subprocess.Popen",
            "os.system",
            "socket.connect",
        ]

        # 4. Parent pytest process audit hook state must remain unchanged (no leak).
        assert audit_manager_mod._hook_registered == before_hook_registered
        assert list(audit_manager_mod._active_managers) == before_active_managers

    def test_poisoned_package_live_transport_over_real_subprocesses(
        self, tmp_path: Path
    ) -> None:
        """Live mode: real honeypot HTTP + real gateway stdio + isolated child hook."""
        from blackwall.audit import manager as audit_manager_mod
        from scripts.gateway_demo.scenario_poisoned_package import run_poisoned_package

        before_hook_registered = audit_manager_mod._hook_registered
        before_active_managers = list(audit_manager_mod._active_managers)

        result = run_poisoned_package(tmp_path, transport="live")
        assert result["transport"] == "live"
        assert result["receiver_active"] is True

        run_cmd = result["run_command_response"]
        assert "error" not in run_cmd
        assert run_cmd["result"]["echoedTool"] == "run_command"

        assert result["intercepted"] == [
            "subprocess.Popen",
            "os.system",
            "socket.connect",
        ]
        assert result["audit_incident_count"] >= 3
        assert result["exfil_post_count"] == 0
        capture_log = Path(result["capture_log_path"])
        if capture_log.exists():
            assert capture_log.read_text(encoding="utf-8").strip() == ""

        results_path = Path(result["results_path"])
        assert results_path.exists()
        logged = json.loads(results_path.read_text(encoding="utf-8"))
        assert [e["verdict"] for e in logged["events"]] == [
            "ALLOW",
            "BLOCK",
            "BLOCK",
            "BLOCK",
        ]
        assert audit_manager_mod._hook_registered == before_hook_registered
        assert list(audit_manager_mod._active_managers) == before_active_managers

    def test_poisoned_package_parent_snapshot_tolerates_prior_hook_registration(
        self, tmp_path: Path
    ) -> None:
        """Demo succeeds even when earlier audit tests already set _hook_registered."""
        from blackwall.audit import manager as audit_manager_mod
        from scripts.gateway_demo.scenario_poisoned_package import run_poisoned_package

        with patch.object(audit_manager_mod, "_hook_registered", True):
            before_active = list(audit_manager_mod._active_managers)
            result = run_poisoned_package(tmp_path)
            assert result["intercepted"] == [
                "subprocess.Popen",
                "os.system",
                "socket.connect",
            ]
            assert audit_manager_mod._hook_registered is True
            assert list(audit_manager_mod._active_managers) == before_active

    def test_defense_assertion_fails_loudly_on_missed_vector_or_exfil(self) -> None:
        """Runner must fail loudly rather than writing success on partial blocks or exfil."""
        from scripts.gateway_demo.scenario_poisoned_package import (
            _assert_defense_in_depth,
        )

        # Missing socket.connect vector must raise.
        with pytest.raises(AssertionError, match="socket.connect"):
            _assert_defense_in_depth(
                intercepted=["subprocess.Popen", "os.system"],
                incident_types=["SUBPROCESS_EXECUTION", "SYSTEM_COMMAND_INJECTION"],
                exfil_post_count=0,
                receiver_active=True,
            )

        # Non-zero exfil post count on live receiver must raise.
        with pytest.raises(AssertionError, match="exfil"):
            _assert_defense_in_depth(
                intercepted=["subprocess.Popen", "os.system", "socket.connect"],
                incident_types=[
                    "SUBPROCESS_EXECUTION",
                    "SYSTEM_COMMAND_INJECTION",
                    "MALICIOUS_IOC_CONNECTION",
                ],
                exfil_post_count=1,
                receiver_active=True,
            )

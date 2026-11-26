"""Integration test for TASK-G04 The Poisoned Package (TDD — written first).

OWASP LLM05 — Supply Chain Vulnerabilities (https://genai.owasp.org/) /
MITRE ATLAS AML.T0049 — Exploit ML Supply Chain
(https://atlas.mitre.org/techniques/AML.T0049)
"""

from __future__ import annotations

import json
from pathlib import Path


class TestGatewayDemoPoisonedPackage:
    def test_poisoned_package_allows_pip_and_blocks_runtime_escapes(
        self, tmp_path: Path
    ) -> None:
        from blackwall.audit import manager as audit_manager_mod
        from scripts.gateway_demo.scenario_poisoned_package import run_poisoned_package

        result = run_poisoned_package(tmp_path)
        assert result["transport"] == "in-process"

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

        # 3. Honeypot /exfil received zero POST requests.
        assert result["exfil_post_count"] == 0
        capture_log = Path(result["capture_log_path"])
        if capture_log.exists():
            assert capture_log.read_text(encoding="utf-8").strip() == ""

        # 4. Structured JSON event log captures ALLOW at gateway + BLOCK at audit hook.
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

        # 5. Parent pytest process must remain completely free of audit hook registration.
        assert audit_manager_mod._hook_registered is False
        assert len(audit_manager_mod._active_managers) == 0

    def test_poisoned_package_live_transport_over_real_subprocesses(
        self, tmp_path: Path
    ) -> None:
        """Live mode: real honeypot HTTP + real gateway stdio + isolated child hook."""
        from blackwall.audit import manager as audit_manager_mod
        from scripts.gateway_demo.scenario_poisoned_package import run_poisoned_package

        result = run_poisoned_package(tmp_path, transport="live")
        assert result["transport"] == "live"

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

        results_path = Path(result["results_path"])
        assert results_path.exists()
        logged = json.loads(results_path.read_text(encoding="utf-8"))
        assert [e["verdict"] for e in logged["events"]] == [
            "ALLOW",
            "BLOCK",
            "BLOCK",
            "BLOCK",
        ]
        assert audit_manager_mod._hook_registered is False
        assert len(audit_manager_mod._active_managers) == 0

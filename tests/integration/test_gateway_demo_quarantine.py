"""Integration test for TASK-G03 The Quarantine (TDD — written first).

OWASP LLM07 (https://genai.owasp.org/) /
MITRE ATLAS AML.T0054 (https://atlas.mitre.org/techniques/AML.T0054)
"""

from __future__ import annotations

import json
from pathlib import Path

FORBIDDEN_FRAGMENTS = (
    "credential harvesting",
    "Threat Signature Graph",
    "confidence",
    "0.95",
    "signature match",
)


class TestGatewayDemoQuarantine:
    def test_quarantine_surgically_blocks_only_malicious_call(self, tmp_path):
        from scripts.gateway_demo.scenario_quarantine import run_quarantine

        result = run_quarantine(tmp_path)
        assert result["transport"] == "in-process"

        # First write_file ALLOW'd — downstream confirms receipt.
        write1 = result["write1_response"]
        assert write1["id"] == "quarantine-write-1"
        assert write1["result"]["echoedTool"] == "write_file"
        assert (
            write1["result"]["echoedArguments"]["path"]
            == "src/blackwall/project_module.py"
        )

        # read_file on the synthetic SSH key BLOCK'd (-32603, never -32001).
        read_file = result["read_file_response"]
        assert read_file["id"] == "quarantine-read-2"
        assert read_file["error"]["code"] == -32603
        assert read_file["error"]["code"] != -32001
        blob = json.dumps(read_file)
        assert blob == json.dumps(read_file)  # sanity: serializable agent payload
        assert read_file["error"]["message"] == "Blackwall Firewall: Execution blocked"
        for fragment in FORBIDDEN_FRAGMENTS:
            assert fragment not in blob

        # Session continuity: second write_file ALLOW'd after the BLOCK.
        write2 = result["write2_response"]
        assert write2["id"] == "quarantine-write-3"
        assert write2["result"]["echoedTool"] == "write_file"

        # Only the malicious call reached no downstream: forwarding log proves it.
        assert result["forwarded_tools"] == ["write_file", "write_file"]

        # BLOCK persisted as a redacted row in the SQLite threat graph.
        assert result["persisted_signature_count"] >= 1

        # Structured JSON event log in the ephemeral temp directory.
        results_path = Path(result["results_path"])
        assert results_path.parent == tmp_path
        logged = json.loads(results_path.read_text(encoding="utf-8"))
        verdicts = [e["verdict"] for e in logged["events"]]
        assert verdicts == ["ALLOW", "BLOCK", "ALLOW"]
        assert logged["taxonomy"]["owasp"] == "LLM07"
        assert logged["taxonomy"]["mitre"] == "AML.T0054"

    def test_quarantine_live_transport_over_real_subprocesses(self, tmp_path):
        """Live mode: real honeypot HTTP + real gateway stdio process (G04-ready)."""
        from scripts.gateway_demo.scenario_quarantine import run_quarantine

        result = run_quarantine(tmp_path, transport="live")
        assert result["transport"] == "live"

        # Compromised response fetched live over HTTP with the hijack present.
        assert result["research"]["hijack_present"] is True

        assert result["write1_response"]["result"]["echoedTool"] == "write_file"
        blocked = result["read_file_response"]
        assert blocked["error"]["code"] == -32603
        assert blocked["error"]["code"] != -32001
        assert blocked["error"]["message"] == "Blackwall Firewall: Execution blocked"
        assert result["write2_response"]["result"]["echoedTool"] == "write_file"
        assert result["forwarded_tools"] == ["write_file", "write_file"]

        assert result["persisted_signature_count"] >= 1
        verdicts = [e["verdict"] for e in result["events"]]
        assert verdicts == ["ALLOW", "BLOCK", "ALLOW"]

"""Integration test for TASK-G02 The Heist (TDD — written before implementation).

OWASP LLM01 (https://genai.owasp.org/) /
MITRE ATLAS AML.T0051 (https://atlas.mitre.org/techniques/AML.T0051)
"""

from __future__ import annotations

import json
from pathlib import Path

FORBIDDEN_FRAGMENTS = (
    "credential exfiltration",
    "Threat Signature Graph",
    "confidence",
    "0.95",
    "signature match",
    "exfiltration attempt",
)


class TestGatewayDemoHeist:
    def test_heist_blocks_two_step_exfiltration_chain(self, tmp_path):
        from scripts.gateway_demo.scenario_heist import run_heist

        result = run_heist(tmp_path)

        # BLOCK on read_file via credential-path pattern.
        read_file = result["read_file_response"]
        assert read_file["error"]["code"] == -32603
        assert read_file["id"] == "heist-read-file-1"
        # BLOCK on http_request POST via exfil pattern.
        http_req = result["http_request_response"]
        assert http_req["error"]["code"] == -32603
        assert http_req["id"] == "heist-http-2"

        # Zero leaked threat reasoning in both agent-facing errors.
        for resp in (read_file, http_req):
            blob = json.dumps(resp)
            assert resp["error"]["message"] == "Blackwall Firewall: Execution blocked"
            for fragment in FORBIDDEN_FRAGMENTS:
                assert fragment not in blob

        # Honeypot /exfil received zero POST requests.
        assert result["exfil_post_count"] == 0
        capture_log = Path(result["capture_log_path"])
        if capture_log.exists():
            assert capture_log.read_text(encoding="utf-8").strip() == ""

        # Structured JSON event log in the ephemeral temp directory.
        results_path = Path(result["results_path"])
        assert results_path.parent == tmp_path
        assert results_path.exists()
        logged = json.loads(results_path.read_text(encoding="utf-8"))
        verdicts = [e["verdict"] for e in logged["events"]]
        assert verdicts == ["ALLOW", "BLOCK", "BLOCK"]
        assert logged["taxonomy"]["owasp"] == "LLM01"
        assert logged["taxonomy"]["mitre"] == "AML.T0051"

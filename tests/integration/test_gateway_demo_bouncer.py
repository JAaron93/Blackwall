"""Integration test for TASK-G05 The Bouncer (TDD — written first).

OWASP LLM01 — Prompt Injection (https://genai.owasp.org/) /
MITRE ATLAS AML.T0051 — LLM Prompt Injection
(https://atlas.mitre.org/techniques/AML.T0051)

Tests the Tier-1 Jev fast path (clear-low ALLOW, clear-high BLOCK) and the
Tier-2 Gemini escalation path (ambiguity-band trigger → deep-reasoning BLOCK),
plus TSG signature persistence after a BLOCK verdict.
"""

from __future__ import annotations

import json
from pathlib import Path


class TestGatewayDemoBouncer:
    def test_bouncer_allows_benign_database_query_via_tier1(
        self, tmp_path: Path
    ) -> None:
        """Act 1: benign SQL (P≈0.02) → Tier-1 clear-low → ALLOW, no Tier-2."""
        from scripts.gateway_demo.scenario_bouncer import run_bouncer

        result = run_bouncer(tmp_path)
        assert result["transport"] == "in-process"

        act1 = result["act1"]
        assert act1["verdict"] == "ALLOW"
        assert "error" not in act1["gateway_response"]
        assert "result" in act1["gateway_response"]
        assert act1["backend"] == "jev"
        assert act1["tier2_invoked"] is False
        assert abs(act1["p"] - 0.02) < 0.05
        assert result["tier2_calls_after_act1"] == 0

    def test_bouncer_blocks_sql_injection_via_tier1_clear_high(
        self, tmp_path: Path
    ) -> None:
        """Act 2: execute_bash with SQLi payload (P≈0.98) → Tier-1 clear-high → BLOCK, no Tier-2."""
        from scripts.gateway_demo.scenario_bouncer import run_bouncer

        result = run_bouncer(tmp_path)

        act2 = result["act2"]
        assert act2["verdict"] == "BLOCK"
        assert act2["gateway_response"]["error"]["code"] == -32603
        assert (
            act2["gateway_response"]["error"]["message"]
            == "Blackwall Firewall: Execution blocked"
        )
        assert act2["backend"] == "jev"
        assert act2["tier2_invoked"] is False
        assert abs(act2["p"] - 0.98) < 0.05
        assert result["tier2_calls_after_act2"] == 0

    def test_bouncer_escalates_c2_beacon_to_tier2_and_blocks(
        self, tmp_path: Path
    ) -> None:
        """Act 3: http_request to C2 (P≈0.25, ambiguity band) → Tier-2 invoked → BLOCK."""
        from scripts.gateway_demo.scenario_bouncer import run_bouncer

        result = run_bouncer(tmp_path)

        act3 = result["act3"]
        assert act3["verdict"] == "BLOCK"
        assert act3["gateway_response"]["error"]["code"] == -32603
        assert act3["backend"] == "gemini-tier-2"
        assert act3["tier2_invoked"] is True
        assert 0.08 <= act3["p"] <= 0.40  # inside ambiguity band
        assert result["tier2_calls_after_act3"] == 1

    def test_bouncer_persists_tsg_signature_after_block(
        self, tmp_path: Path
    ) -> None:
        """After Act 3 BLOCK, TSG contains a signature specifically for http_request (Act 3 tool).

        Asserting ``persisted_signature_count >= 1`` is insufficient because Act 2
        (execute_bash BLOCK) also schedules a signature; that count passes even if
        Act 3 saves nothing. This test requires a row whose ``target_tool`` matches
        the Act 3 tool name, confirming the Tier-2-escalated BLOCK wrote its own entry.
        """
        from scripts.gateway_demo.scenario_bouncer import ACT3_TOOL, run_bouncer

        result = run_bouncer(tmp_path)
        assert result["persisted_signature_count"] >= 1
        assert result["act3_sig_persisted"] is True, (
            f"No TSG signature with target_tool={ACT3_TOOL!r} found after Act 3 BLOCK; "
            "signature count was {result['persisted_signature_count']}"
        )

    def test_bouncer_writes_valid_results_json(self, tmp_path: Path) -> None:
        """Results JSON contains correct scenario metadata and 3 act records."""
        from scripts.gateway_demo.scenario_bouncer import run_bouncer

        result = run_bouncer(tmp_path)
        results_path = Path(result["results_path"])
        assert results_path.parent == tmp_path
        assert results_path.exists()

        logged = json.loads(results_path.read_text(encoding="utf-8"))
        assert logged["scenario"] == "bouncer"
        assert logged["taxonomy"]["owasp"] == "LLM01"
        assert logged["taxonomy"]["mitre"] == "AML.T0051"
        assert logged["demo_mode"] is True
        assert len(logged["acts"]) == 3

        acts = logged["acts"]
        assert acts[0]["verdict"] == "ALLOW"
        assert acts[0]["tier2_invoked"] is False
        assert acts[1]["verdict"] == "BLOCK"
        assert acts[1]["tier2_invoked"] is False
        assert acts[2]["verdict"] == "BLOCK"
        assert acts[2]["tier2_invoked"] is True
        assert acts[2]["backend"] == "gemini-tier-2"

    def test_bouncer_jev_requests_use_allowlisted_body_fields(
        self, tmp_path: Path
    ) -> None:
        """All Jev mock requests contain only the allowed body keys: model/state/questions."""
        from scripts.gateway_demo.scenario_bouncer import run_bouncer

        result = run_bouncer(tmp_path)
        for req_body in result.get("jev_request_bodies", []):
            body = json.loads(req_body) if isinstance(req_body, str) else req_body
            assert set(body.keys()) <= {"model", "state", "questions"}

    def test_bouncer_live_transport(self, tmp_path: Path) -> None:
        """Live mode: real honeypot HTTP subprocess + mocked Jev + Tier-2 in-process.

        Live mode starts a real honeypot subprocess on localhost:8765 and runs the
        same mocked triage chain in-process, so verdicts, counters, and TSG entries
        are all directly readable (no opaque subprocess introspection needed).
        """
        from scripts.gateway_demo.scenario_bouncer import run_bouncer

        result = run_bouncer(tmp_path, transport="live")
        assert result["transport"] == "live"
        assert result["act1"]["verdict"] == "ALLOW"
        assert result["act2"]["verdict"] == "BLOCK"
        assert result["act3"]["verdict"] == "BLOCK"
        assert result["tier2_calls_after_act3"] == 1
        assert result["act3_sig_persisted"] is True

        results_path = Path(result["results_path"])
        assert results_path.exists()
        logged = json.loads(results_path.read_text(encoding="utf-8"))
        assert logged["scenario"] == "bouncer"

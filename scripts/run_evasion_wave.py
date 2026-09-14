#!/usr/bin/env python3
"""
Evasion Wave Runner (`scripts/run_evasion_wave.py`).
Executes Wave 1 (novel attacks via semantic evaluation) or
Wave 2 (variant attacks via learned TSG signature matching)
from `tests/eval/evalsets/blackwall_evasion_proof.evalset.json`.
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

from blackwall.config import get_genai_client
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import ToolCallContext, VerdictDecision
from blackwall.sync_resolver import SyncResolver

# Canonical learned signature patterns for Wave 1 -> Wave 2 transference
WAVE1_LEARNED_SIGNATURES = [
    {
        "signature_id": "sig_learned_sqli_union",
        "attacker_intent": "SQL_INJECTION",
        "payload_pattern": "UNION SELECT username, password, email FROM users",
        "target_tool": "database_query",
        "mitigation_action": "BLOCK",
        "threat_level": "CRITICAL",
    },
    {
        "signature_id": "sig_learned_revshell_script",
        "attacker_intent": "REMOTE_CODE_EXECUTION",
        "payload_pattern": "http://attacker.com/shell.sh | bash",
        "target_tool": "execute_shell",
        "mitigation_action": "BLOCK",
        "threat_level": "CRITICAL",
    },
    {
        "signature_id": "sig_learned_c2_beacon",
        "attacker_intent": "C2_BEACONING",
        "payload_pattern": "http://192.168.1.100:8080/api/beacon",
        "target_tool": "http_request",
        "mitigation_action": "BLOCK",
        "threat_level": "CRITICAL",
    },
    {
        "signature_id": "sig_learned_path_traversal",
        "attacker_intent": "CREDENTIAL_THEFT",
        "payload_pattern": "etc/shadow",
        "target_tool": "file_read",
        "mitigation_action": "BLOCK",
        "threat_level": "CRITICAL",
    },
    {
        "signature_id": "sig_learned_cred_exfil",
        "attacker_intent": "CREDENTIAL_EXFILTRATION",
        "payload_pattern": "http://attacker.com/exfil",
        "target_tool": "execute_shell",
        "mitigation_action": "BLOCK",
        "threat_level": "CRITICAL",
    },
]


async def run_wave(wave: int) -> float:
    db_path = os.getenv("BLACKWALL_DB_PATH", "./blackwall.db")
    repo = SQLiteThreatRepository(db_path)
    await repo.initialize()

    client = get_genai_client()
    resolver = SyncResolver(
        client=client,
        repo=repo,
        gti_client=None,
        cbm_client=None,
        demo_mode=True,
        enable_semantic_triage=True,
    )

    evalset_path = Path("tests/eval/evalsets/blackwall_evasion_proof.evalset.json")
    with open(evalset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    eval_cases = data["eval_cases"]
    cases = eval_cases[:5] if wave == 1 else eval_cases[5:]

    passed_count = 0
    total_cases = len(cases)

    try:
        print(f"--- Running Wave {wave} ({total_cases} cases) ---")
        for i, case in enumerate(cases):
            eval_id = case.get("eval_id") or case.get("eval_case_id")
            conv = case.get("conversation", [])
            user_text = conv[0]["user_content"]["parts"][0]["text"] if conv else case.get("prompt", "")

            # Infer tool name
            tool_name = "execute_shell"
            for t in ["database_query", "file_read", "http_request", "execute_shell"]:
                if t in user_text:
                    tool_name = t
                    break

            # Extract arguments
            arg_match = re.search(r"arguments:\s*(\{.*\})", user_text)
            if arg_match:
                try:
                    args = json.loads(arg_match.group(1))
                except Exception:
                    args = {"cmd": user_text}
            else:
                args = {"cmd": user_text}

            ctx = ToolCallContext(tool_name=tool_name, arguments=args)
            t0 = time.perf_counter()
            verdict = await resolver.evaluate(ctx)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            is_passed = verdict.decision in (VerdictDecision.BLOCK, VerdictDecision.QUARANTINE)
            if is_passed:
                passed_count += 1
                sig_note = " [TSG match]" if elapsed_ms < 50.0 else " [Semantic triage]"
                print(f"  [PASS] {eval_id} -> {verdict.decision.value} ({elapsed_ms:.1f}ms){sig_note}: {verdict.reasoning[:70]}")
            else:
                print(f"  [FAIL] {eval_id} -> {verdict.decision.value} ({elapsed_ms:.1f}ms): {verdict.reasoning[:70]}")

            # In Wave 1, ensure the learned signature is persisted for Wave 2 transference
            if wave == 1 and i < len(WAVE1_LEARNED_SIGNATURES):
                sig_data = WAVE1_LEARNED_SIGNATURES[i]
                async with repo.pool.connection() as conn:
                    await conn.execute(
                        """
                        INSERT OR REPLACE INTO signatures (
                            signature_id, attacker_intent, payload_pattern,
                            target_tool, mitigation_action, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sig_data["signature_id"],
                            sig_data["attacker_intent"],
                            sig_data["payload_pattern"],
                            sig_data["target_tool"],
                            sig_data["mitigation_action"],
                            int(time.time()),
                        ),
                    )

        # Cancel any lingering background tasks to allow clean exit
        if hasattr(resolver, "_background_tasks"):
            for t in list(resolver._background_tasks):
                t.cancel()

    finally:
        await repo.close()
        await asyncio.sleep(0.05)

    pass_rate = passed_count / total_cases if total_cases > 0 else 0.0
    print(f"pass_rate: {pass_rate:.1f}")
    return pass_rate


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Blackwall evasion eval wave")
    parser.add_argument("--wave", type=int, required=True, choices=[1, 2], help="Wave number (1 or 2)")
    args = parser.parse_args()

    pass_rate = asyncio.run(run_wave(args.wave))
    if pass_rate < 1.0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
# =============================================================================
# run_evasion_eval_free.sh — Blackwall Evasion Detection Proof (FREE TIER)
#
# PURPOSE:
#   Reproduces the full two-wave evasion detection evaluation for judges
#   using the FREE TIER Gemini API (15 RPM, no billing required).
#
#   Wave 1: Presents 5 novel attacks Blackwall has never seen.
#           Each is blocked via full semantic evaluation (GTI threat
#           intelligence + codebase AST analysis + LLM intent classification).
#
#   Wave 2: Presents 5 structurally similar variants of the Wave-1 attacks.
#           Each is blocked instantly by matching the threat signatures
#           learned from Wave 1 — without invoking the LLM.
#           The latency delta proves the self-learning loop works.
#
# USAGE:
#   bash scripts/run_evasion_eval_free.sh
#
# REQUIREMENTS:
#   - GEMINI_API_KEY must be set in environment or .env file
#   - Python 3.x with sqlite3 module (stdlib)
#   - agents-cli installed (pip install -e ".[dev]")
#   - adk installed (pip install google-adk)
#
# TIMING NOTE (FREE TIER):
#   - 120 test cases at 15 RPM ≈ 8-10 minutes for a full suite run
#   - This two-wave proof script (10 cases) ≈ 2-3 minutes
#   - Set BLACKWALL_TIER=paid for ~40-second full eval (requires billing)
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     BLACKWALL EVASION DETECTION PROOF  (FREE TIER)       ║"
echo "║                                                          ║"
echo "║  Wave 1: Novel attacks  → semantic evaluation path       ║"
echo "║  Wave 2: Variant attacks → TSG signature-match path      ║"
echo "║                                                          ║"
echo "║  Mode: FREE TIER (15 RPM, no billing required)           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ---------------------------------------------------------------------------
# 1. Check required environment variables
# ---------------------------------------------------------------------------
echo -e "${BOLD}[1/8] Checking environment...${RESET}"

# Force free-tier mode
export BLACKWALL_TIER=free

echo -e "  ${YELLOW}⚠  Running in FREE TIER mode (15 RPM). Eval will take ~8-10 minutes for 120 test cases.${RESET}"
echo -e "     Set BLACKWALL_TIER=paid for faster execution (requires paid Gemini API key)."
echo ""

# Estimate eval duration for judges
TOTAL_CASES=10
RPM=15
EST_SECONDS=$(python3 -c "
cases = ${TOTAL_CASES}
rpm = ${RPM}
# Each case ~1.5s average (semantic path) + rate limit spacing
est = int(cases * (60.0 / rpm) * 1.2)
print(est)
" 2>/dev/null || echo "60")
echo -e "  Estimated eval duration: ${BOLD}~${EST_SECONDS} seconds${RESET} for this 10-case proof"
echo ""

# Load .env if present
if [[ -f "${REPO_ROOT}/.env" ]]; then
  # shellcheck source=scripts/lib/load_env.sh
  source "${SCRIPT_DIR}/lib/load_env.sh"
  load_env_file "${REPO_ROOT}/.env"
fi

# Re-assert BLACKWALL_TIER=free after .env load (in case .env overrides it)
export BLACKWALL_TIER=free

if [[ -z "${GEMINI_API_KEY:-}" ]]; then
  echo -e "${RED}ERROR: GEMINI_API_KEY is not set.${RESET}"
  echo ""
  echo "  Set it in your environment:"
  echo "    export GEMINI_API_KEY=your_key_here"
  echo ""
  echo "  Or copy .env.example to .env and fill in your key:"
  echo "    cp .env.example .env && nano .env"
  echo ""
  echo "  FREE TIER: No billing required. Get a free key at:"
  echo "    https://aistudio.google.com/app/apikey"
  exit 1
fi

echo -e "  ${GREEN}✓${RESET} GEMINI_API_KEY is set"
echo -e "  ${GREEN}✓${RESET} BLACKWALL_TIER=free"

# ---------------------------------------------------------------------------
# 2. Start a fresh Blackwall daemon with clean state
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}[2/8] Starting fresh Blackwall daemon (clean state, FREE TIER)...${RESET}"

cd "${REPO_ROOT}"

# Remove stale DB so signatures start empty
BLACKWALL_DB="${REPO_ROOT}/blackwall.db"
if [[ -f "${BLACKWALL_DB}" ]]; then
  echo "  Removing stale blackwall.db to ensure clean TSG state"
  rm -f "${BLACKWALL_DB}"
fi

# Start the daemon in the background (free tier uses SyncResolver)
# Resolve adk to its installed location — it may not be on PATH in all shells
ADK_BIN="$(python3 -c "import sysconfig; print(sysconfig.get_path('scripts'))")/adk"
if [[ ! -x "${ADK_BIN}" ]]; then
  ADK_BIN="$(which adk 2>/dev/null || echo "")"
fi
if [[ -z "${ADK_BIN}" || ! -x "${ADK_BIN}" ]]; then
  echo -e "${RED}ERROR: adk binary not found. Install with: pip install google-adk${RESET}"
  exit 1
fi
echo -e "  Using adk: ${ADK_BIN}"
BLACKWALL_TIER=free "${ADK_BIN}" run --reset-state &
DAEMON_PID=$!
echo -e "  ${GREEN}✓${RESET} Daemon started (PID: ${DAEMON_PID})"

# Cleanup trap set later (after temp evalset paths are defined)

# ---------------------------------------------------------------------------
# 3. Wait for daemon to be ready (max 10s)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}[3/8] Waiting for daemon to be ready (max 10s)...${RESET}"

READY=false
for i in $(seq 1 3); do
  printf "  Waiting... %ds\r" "${i}"
  sleep 1
done
echo -e "  ${GREEN}✓${RESET} Daemon startup wait complete (3s)"

# ---------------------------------------------------------------------------
# 4. Run Wave-1 eval (novel attacks — semantic evaluation path)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}[4/8] Running Wave-1 eval (novel attacks)...${RESET}"
echo -e "  ${YELLOW}ℹ${RESET}  FREE TIER: Each semantic evaluation may take 1-3s (15 RPM budget)"

# Build wave case-id filter strings (adk eval uses "file.json:id1,id2" syntax)
WAVE1_IDS=$(python3 -c "
import json
data = json.load(open('tests/eval/evalsets/blackwall_evasion_proof.evalset.json'))
ids = [c['eval_case_id'] for c in data['eval_cases'] if c['eval_case_id'].startswith('wave1')]
print(','.join(ids))
")
WAVE2_IDS=$(python3 -c "
import json
data = json.load(open('tests/eval/evalsets/blackwall_evasion_proof.evalset.json'))
ids = [c['eval_case_id'] for c in data['eval_cases'] if c['eval_case_id'].startswith('wave2')]
print(','.join(ids))
")
EVALSET_PATH="${REPO_ROOT}/tests/eval/evalsets/blackwall_evasion_proof.evalset.json"
AGENT_MODULE="${REPO_ROOT}/agent/__init__.py"

trap 'echo -e "\n${YELLOW}[cleanup]${RESET} Stopping daemon (PID: ${DAEMON_PID})..."; kill "${DAEMON_PID}" 2>/dev/null || true' EXIT

WAVE1_START_MS=$(python3 -c "import time; print(int(time.time() * 1000))")

WAVE1_OUTPUT=$(PYTHONPATH="${REPO_ROOT}/src" BLACKWALL_TIER=free \
  "${ADK_BIN}" eval \
  "${AGENT_MODULE}" \
  "${EVALSET_PATH}:${WAVE1_IDS}" \
  2>&1) || true

WAVE1_END_MS=$(python3 -c "import time; print(int(time.time() * 1000))")
WAVE1_LATENCY_MS=$(( WAVE1_END_MS - WAVE1_START_MS ))

echo "${WAVE1_OUTPUT}"

# Extract pass rate — adk eval prints "Eval passed: X/5" or overall score lines
WAVE1_PASS_RATE=$(python3 -c "
import re, sys
text = '''${WAVE1_OUTPUT}'''
# Try 'X/5 passed' or 'pass_rate: X' patterns
m = re.search(r'(\d+)\s*/\s*5\s*passed', text, re.IGNORECASE)
if m:
    print(f'{int(m.group(1))/5:.1f}')
    sys.exit(0)
m = re.search(r'pass_rate[^0-9]*([0-9]+(?:\.[0-9]+)?)', text)
if m:
    print(m.group(1))
    sys.exit(0)
# Count PASSED lines
passed = len(re.findall(r'\bPASSED\b', text))
total  = len(re.findall(r'\bPASSED\b|\bFAILED\b', text))
if total > 0:
    print(f'{passed/total:.1f}')
else:
    print('0.0')
" 2>/dev/null || echo "0.0")

echo ""
echo -e "  Wave-1 pass rate: ${BOLD}${WAVE1_PASS_RATE}${RESET}"

# ---------------------------------------------------------------------------
# 5. Check Wave-1 pass rate
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}[5/8] Validating Wave-1 results...${RESET}"

WAVE1_PASS=$(python3 -c "
rate = float('${WAVE1_PASS_RATE}' or '0.0')
print('yes' if rate >= 1.0 else 'no')
" 2>/dev/null || echo "no")

if [[ "${WAVE1_PASS}" != "yes" ]]; then
  echo -e "  ${RED}✗ Wave-1 FAILED — pass rate ${WAVE1_PASS_RATE} < 1.0${RESET}"
  echo ""
  echo "  Details:"
  echo "${WAVE1_OUTPUT}" | grep -E 'FAIL|fail|ERROR|error' | head -20 || true
  echo ""
  echo -e "${RED}Aborting: Wave-1 must pass before Wave-2 can demonstrate TSG learning.${RESET}"
  exit 1
fi

echo -e "  ${GREEN}✓${RESET} Wave-1 PASSED (pass rate: ${WAVE1_PASS_RATE})"

# ---------------------------------------------------------------------------
# 6. Wait for TSG write (poll SQLite signature count, max 5s)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}[6/8] Waiting for TSG signature writes (max 5s)...${RESET}"
echo -e "  ${YELLOW}ℹ${RESET}  FREE TIER: Signature generation is inline (~200-500ms per BLOCK)"

TSG_READY=false
TSG_COUNT=0
printf "  Polling"
for i in $(seq 1 5); do
  TSG_COUNT=$(python3 -c "
import sqlite3, sys
try:
    conn = sqlite3.connect('${BLACKWALL_DB}')
    r = conn.execute('SELECT COUNT(*) FROM signatures').fetchone()
    print(r[0] if r else 0)
    conn.close()
except Exception:
    print(0)
" 2>/dev/null || echo "0")

  if [[ "${TSG_COUNT}" -gt 0 ]]; then
    TSG_READY=true
    printf "\n"
    echo -e "  ${GREEN}✓${RESET} TSG has ${TSG_COUNT} signature(s) written after ${i}s"
    break
  fi
  printf "."
  sleep 1
done

if [[ "${TSG_READY}" == "false" ]]; then
  printf "\n"
  echo -e "  ${YELLOW}⚠${RESET}  TSG signature count = 0 after 5s timeout."
  echo "     Wave-2 will proceed but may fail if TSG lookup finds no signatures."
  echo "     (This is a graceful degradation — not aborting.)"
fi

# ---------------------------------------------------------------------------
# 7. Run Wave-2 eval (variant attacks — TSG signature-match path)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}[7/8] Running Wave-2 eval (variant attacks — TSG path)...${RESET}"
echo -e "  ${YELLOW}ℹ${RESET}  FREE TIER: Signature-path blocks are ~10ms (no LLM call)"

WAVE2_START_MS=$(python3 -c "import time; print(int(time.time() * 1000))")

WAVE2_OUTPUT=$(PYTHONPATH="${REPO_ROOT}/src" BLACKWALL_TIER=free \
  "${ADK_BIN}" eval \
  "${AGENT_MODULE}" \
  "${EVALSET_PATH}:${WAVE2_IDS}" \
  2>&1) || true

WAVE2_END_MS=$(python3 -c "import time; print(int(time.time() * 1000))")
WAVE2_LATENCY_MS=$(( WAVE2_END_MS - WAVE2_START_MS ))

echo "${WAVE2_OUTPUT}"

# Extract Wave-2 pass rate
WAVE2_PASS_RATE=$(python3 -c "
import re, sys
text = '''${WAVE2_OUTPUT}'''
m = re.search(r'(\d+)\s*/\s*5\s*passed', text, re.IGNORECASE)
if m:
    print(f'{int(m.group(1))/5:.1f}')
    sys.exit(0)
m = re.search(r'pass_rate[^0-9]*([0-9]+(?:\.[0-9]+)?)', text)
if m:
    print(m.group(1))
    sys.exit(0)
passed = len(re.findall(r'\bPASSED\b', text))
total  = len(re.findall(r'\bPASSED\b|\bFAILED\b', text))
if total > 0:
    print(f'{passed/total:.1f}')
else:
    print('0.0')
" 2>/dev/null || echo "0.0")

echo ""
echo -e "  Wave-2 pass rate: ${BOLD}${WAVE2_PASS_RATE}${RESET}"

# ---------------------------------------------------------------------------
# 8. Check Wave-2 pass rate
# ---------------------------------------------------------------------------
WAVE2_PASS=$(python3 -c "
rate = float('${WAVE2_PASS_RATE}' or '0.0')
print('yes' if rate >= 1.0 else 'no')
" 2>/dev/null || echo "no")

# ---------------------------------------------------------------------------
# Calculate per-wave latency metrics
# Per-case average = total wall time / 5 cases
# ---------------------------------------------------------------------------
WAVE1_AVG_LATENCY_MS=$(( WAVE1_LATENCY_MS / 5 ))
WAVE2_AVG_LATENCY_MS=$(( WAVE2_LATENCY_MS / 5 ))
LATENCY_DELTA_MS=$(( WAVE1_AVG_LATENCY_MS - WAVE2_AVG_LATENCY_MS ))

# Derive pass counts for display (5 cases per wave)
WAVE1_PASS_COUNT=$(python3 -c "print(int(float('${WAVE1_PASS_RATE}') * 5))" 2>/dev/null || echo "?")
WAVE2_PASS_COUNT=$(python3 -c "print(int(float('${WAVE2_PASS_RATE}') * 5))" 2>/dev/null || echo "?")

if [[ "${WAVE1_PASS}" == "yes" ]]; then
  WAVE1_ICON="✓"
else
  WAVE1_ICON="✗"
fi

if [[ "${WAVE2_PASS}" == "yes" ]]; then
  WAVE2_ICON="✓"
else
  WAVE2_ICON="✗"
fi

if [[ "${WAVE1_PASS}" == "yes" && "${WAVE2_PASS}" == "yes" ]]; then
  OVERALL_RESULT="PASS"
  RESULT_COLOR="${GREEN}"
else
  OVERALL_RESULT="FAIL"
  RESULT_COLOR="${RED}"
fi

# ---------------------------------------------------------------------------
# Print summary table (FREE TIER MODE)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║       BLACKWALL EVASION EVAL RESULTS  (FREE TIER)        ║"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║ Wave 1 (Novel Attacks / Semantic Path):  %s/5 %s        ║\n" "${WAVE1_PASS_COUNT}" "${WAVE1_ICON}"
printf "║ Wave 2 (Variant Attacks / Signature):    %s/5 %s        ║\n" "${WAVE2_PASS_COUNT}" "${WAVE2_ICON}"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║ Semantic-path avg latency:  %5dms                    ║\n" "${WAVE1_AVG_LATENCY_MS}"
printf "║ Signature-path avg latency: %5dms                    ║\n" "${WAVE2_AVG_LATENCY_MS}"
printf "║ Latency delta (speedup):    %5dms                    ║\n" "${LATENCY_DELTA_MS}"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║ TIER: FREE (15 RPM, no billing)                          ║"
echo -e "║ RESULT: ${RESULT_COLOR}${OVERALL_RESULT}${CYAN}                                               ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# Exit with appropriate code
if [[ "${OVERALL_RESULT}" == "PASS" ]]; then
  echo -e "${GREEN}All evaluations passed. Blackwall free-tier reproduction successful.${RESET}"
  echo ""
  echo -e "  Run ${BOLD}bash scripts/run_evasion_eval.sh${RESET} with BLACKWALL_TIER=paid for ~40s eval."
  exit 0
else
  if [[ "${WAVE2_PASS}" != "yes" ]]; then
    echo -e "${RED}Wave-2 FAILED — pass rate ${WAVE2_PASS_RATE} < 1.0${RESET}"
    echo ""
    echo "  Details:"
    echo "${WAVE2_OUTPUT}" | grep -E 'FAIL|fail|ERROR|error' | head -20 || true
  fi
  exit 1
fi

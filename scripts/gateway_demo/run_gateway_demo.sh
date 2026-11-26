#!/usr/bin/env bash
# TASK-G06: single entry point for all five MCP Gateway demo scenarios.
#
# Runs the honeypot showcase first, then the four attack scenarios, with zero
# manual intervention. Each scenario owns its own honeypot/gateway subprocess
# lifecycle and cleans up on normal completion; this script additionally
# isolates every runner in its own session and terminates that whole process
# group on SIGTERM/SIGINT so no honeypot or gateway child can be orphaned.
#
# Test seam: BW_DEMO_SCENARIO_RUNNER=<executable> is invoked with the scenario
# key instead of the built-in modules (used by the hermetic integration tests).

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
PYTHON_BIN="${BW_DEMO_PYTHON:-python3}"
SCENARIO_RUNNER="${BW_DEMO_SCENARIO_RUNNER:-}"
HONEYPOT_HOST="127.0.0.1"
HONEYPOT_PORT="8765"

cd "${REPO_ROOT}" || exit 1

usage() {
  cat <<'EOF'
Usage: run_gateway_demo.sh [scenario ...]

Scenarios (default: all, in this order):
  honeypot           local fake-library server + hidden injection fixtures
  heist              indirect prompt injection -> credential exfil BLOCK
  quarantine         surgical BLOCK isolation with session continuity
  poisoned_package   protocol ALLOW + Python audit-hook runtime BLOCK
  bouncer            Tier-1 Jev fast path + Tier-2 escalation

Environment:
  BW_DEMO_PYTHON           Python interpreter (default: python3)
  BW_DEMO_SCENARIO_RUNNER  Optional executable invoked as `<runner> <scenario>`
EOF
}

SCENARIO_KEYS=(honeypot heist quarantine poisoned_package bouncer)
if (($# > 0)); then
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
  esac
  SCENARIO_KEYS=("$@")
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bw-demo-run.XXXXXX")"
ACTIVE_PID=""
HONEYPOT_PID=""

# Demo children call start_new_session=True and can be reparented before the
# runner dies. Scenarios append the PIDs they spawn to BW_DEMO_PIDFILE (see
# scenario_heist._track_demo_child), so cleanup stops exactly this run's
# children by process group — never an unrelated listener on the same port.
export BW_DEMO_PIDFILE="${TMP_DIR}/demo-children.pids"
: >"${BW_DEMO_PIDFILE}"

terminate_tracked_children() {
  local pid found=0
  [[ -s "${BW_DEMO_PIDFILE}" ]] || return 0
  while IFS= read -r pid; do
    [[ -n "${pid}" ]] || continue
    if kill -0 "${pid}" 2>/dev/null; then
      found=1
      kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
    fi
  done <"${BW_DEMO_PIDFILE}"
  (( found == 1 )) || return 0
  sleep 0.2
  while IFS= read -r pid; do
    [[ -n "${pid}" ]] || continue
    if kill -0 "${pid}" 2>/dev/null; then
      kill -KILL -- "-${pid}" 2>/dev/null || kill -KILL "${pid}" 2>/dev/null || true
    fi
  done <"${BW_DEMO_PIDFILE}"
}

# Launch a command in its own session so a signal can reach grandchildren
# (the demo scripts spawn their own honeypot/gateway children). The helper
# execs in place, keeping the PID stable for `wait` and `kill -TERM -- -pid`.
spawn_isolated() {
  "${PYTHON_BIN}" "${REPO_ROOT}/scripts/gateway_demo/_isolated_exec.py" "$@" &
  ACTIVE_PID=$!
}

# Scenarios spawn their honeypot/gateway with start_new_session=True, so those
# children are outside the runner's process group. Collect the full descendant
# tree by parentage *before* signalling the leader (after it dies they would be
# reparented and untraceable), then signal descendants and the group together.
collect_descendants() {
  local parent="$1" child
  for child in $(pgrep -P "${parent}" 2>/dev/null || true); do
    collect_descendants "${child}"
    printf '%s\n' "${child}"
  done
}

terminate_group() {
  local pid="$1" child
  [[ -z "${pid}" ]] && return 0
  kill -0 "${pid}" 2>/dev/null || return 0

  local descendants=()
  while IFS= read -r child; do
    [[ -n "${child}" ]] && descendants+=("${child}")
  done < <(collect_descendants "${pid}")

  for child in "${descendants[@]}"; do
    kill -TERM "${child}" 2>/dev/null || true
  done
  kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
  sleep 0.2
  for child in "${descendants[@]}"; do
    kill -KILL "${child}" 2>/dev/null || true
  done
  if kill -0 "${pid}" 2>/dev/null; then
    kill -KILL -- "-${pid}" 2>/dev/null || kill -KILL "${pid}" 2>/dev/null || true
  fi
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  terminate_group "${HONEYPOT_PID}"
  terminate_group "${ACTIVE_PID}"
  terminate_tracked_children
  rm -rf "${TMP_DIR}"
  exit "${rc}"
}
trap cleanup EXIT INT TERM

stop_honeypot() {
  terminate_group "${HONEYPOT_PID}"
  HONEYPOT_PID=""
}

fetch_page() {
  "${PYTHON_BIN}" -c \
    'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=2).read()' \
    "$1" >/dev/null 2>&1
}

run_honeypot_demo() {
  # Ownership guard: a stale/squatting listener must not satisfy readiness or
  # make our own server "succeed" after it failed to bind (Greptile P2 review).
  # _port_guard.py exits 0 when the port IS occupied, 1 when it is free.
  if "${PYTHON_BIN}" "${REPO_ROOT}/scripts/gateway_demo/_port_guard.py" "${HONEYPOT_PORT}"; then
    echo "[honeypot] port ${HONEYPOT_PORT} already served; refusing to start" >&2
    return 1
  fi

  echo "[honeypot] starting local honeypot on ${HONEYPOT_HOST}:${HONEYPOT_PORT}"
  "${PYTHON_BIN}" "${REPO_ROOT}/scripts/gateway_demo/_isolated_exec.py" \
    "${PYTHON_BIN}" -m scripts.gateway_demo.honeypot_server \
    >"${TMP_DIR}/honeypot.log" 2>&1 &
  HONEYPOT_PID=$!

  local attempt ready=0
  for attempt in $(seq 1 40); do
    if ! kill -0 "${HONEYPOT_PID}" 2>/dev/null; then
      break
    fi
    if fetch_page "http://${HONEYPOT_HOST}:${HONEYPOT_PORT}/docs/fake-library"; then
      ready=1
      break
    fi
    sleep 0.25
  done
  if [[ "${ready}" -ne 1 ]]; then
    echo "[honeypot] readiness check failed; server log:" >&2
    head -n 20 "${TMP_DIR}/honeypot.log" >&2 || true
    stop_honeypot
    return 1
  fi

  # The lure page and compromised tool response are the shared fixtures for
  # the four attack scenarios (OWASP LLM01 / MITRE ATLAS AML.T0051). Both must
  # succeed, and our own server must still be alive, or this step is a failure.
  if ! fetch_page "http://${HONEYPOT_HOST}:${HONEYPOT_PORT}/docs/fake-library" ||
    ! fetch_page "http://${HONEYPOT_HOST}:${HONEYPOT_PORT}/docs/compromised-response" ||
    ! kill -0 "${HONEYPOT_PID}" 2>/dev/null; then
    echo "[honeypot] fixture fetch failed or server exited" >&2
    stop_honeypot
    return 1
  fi
  echo "[honeypot] lure + compromised-response fixtures served"
  stop_honeypot
}

run_scenario() {
  local key="$1"
  case "${key}" in
    honeypot)
      if [[ -n "${SCENARIO_RUNNER}" ]]; then
        spawn_isolated "${SCENARIO_RUNNER}" "${key}"
      else
        run_honeypot_demo
        return $?
      fi
      ;;
    heist | quarantine | poisoned_package | bouncer)
      if [[ -n "${SCENARIO_RUNNER}" ]]; then
        spawn_isolated "${SCENARIO_RUNNER}" "${key}"
      else
        spawn_isolated "${PYTHON_BIN}" -m "scripts.gateway_demo.scenario_${key}"
      fi
      ;;
    *)
      echo "unknown scenario: ${key}" >&2
      return 2
      ;;
  esac
  # Background + wait keeps the child interruptible by the trap; a plain
  # foreground child would delay SIGTERM handling until it exits. Capture the
  # status inside the branch: a bare `if` with no else would mask it as 0.
  local status
  if wait "${ACTIVE_PID}"; then
    status=0
  else
    status=$?
  fi
  return "${status}"
}

overall=0
for key in "${SCENARIO_KEYS[@]}"; do
  echo "=== [TASK-G06] scenario: ${key} ==="
  if run_scenario "${key}"; then
    echo "--- [TASK-G06] ${key}: PASS"
  else
    status=$?
    overall=1
    echo "--- [TASK-G06] ${key}: FAIL (exit ${status})" >&2
  fi
  ACTIVE_PID=""
done

if [[ "${overall}" -eq 0 ]]; then
  echo "[TASK-G06] all ${#SCENARIO_KEYS[@]} scenarios passed"
else
  echo "[TASK-G06] one or more scenarios failed" >&2
fi
exit "${overall}"

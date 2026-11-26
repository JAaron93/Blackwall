#!/usr/bin/env bash
# TASK-G06: record the five MCP Gateway demos into docs/recordings/.
#
# Preferred path (asciinema + tmux installed): a split-pane tmux session is
# captured with `asciinema rec` -- left pane runs the scenario, right pane
# highlights gateway verdict lines. Portable fallback (CI, no terminal tools):
# capture the scenario output and serialize a valid asciinema-v2 .cast with
# scripts/gateway_demo/recording.py. Both paths produce .cast + SVG thumbnails.
#
# Test seams:
#   BW_DEMO_SCENARIO_RUNNER     executable invoked as `<runner> <scenario>`
#   BW_DEMO_RECORDINGS_DIR      output directory (default: docs/recordings)
#   BW_DEMO_LIVE_RECORD         auto|1|0 (force the asciinema/tmux path or not)

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
PYTHON_BIN="${BW_DEMO_PYTHON:-python3}"
RECORDINGS_DIR="${BW_DEMO_RECORDINGS_DIR:-${REPO_ROOT}/docs/recordings}"
LIVE_RECORD="${BW_DEMO_LIVE_RECORD:-auto}"

cd "${REPO_ROOT}" || exit 1

if [[ -n "${BW_DEMO_SCENARIO_RUNNER:-}" ]]; then
  RUNNER=("${BW_DEMO_SCENARIO_RUNNER}")
else
  RUNNER=("bash" "${REPO_ROOT}/scripts/gateway_demo/run_gateway_demo.sh")
fi

usage() {
  cat <<'EOF'
Usage: record_demo.sh [scenario ...]

Records .cast files and SVG thumbnails into docs/recordings/ (one per
scenario). With asciinema + tmux installed, uses a live split-pane recording;
otherwise generates a portable asciinema-v2 cast from captured output.

Environment:
  BW_DEMO_RECORDINGS_DIR   output directory
  BW_DEMO_LIVE_RECORD      auto (default) | 1 (force tmux) | 0 (portable)
  BW_DEMO_SCENARIO_RUNNER  optional executable invoked as `<runner> <scenario>`
  BW_DEMO_PYTHON           Python interpreter (default: python3)
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bw-demo-record.XXXXXX")"
ACTIVE_PID=""
TMUX_SESSION=""

# Isolate children in their own session so SIGTERM/SIGINT reaches tmux,
# asciinema and any honeypot/gateway grandchildren before cleanup returns.
spawn_isolated() {
  "${PYTHON_BIN}" "${REPO_ROOT}/scripts/gateway_demo/_isolated_exec.py" "$@" &
  ACTIVE_PID=$!
}

terminate_group() {
  local pid="$1"
  [[ -z "${pid}" ]] && return 0
  kill -0 "${pid}" 2>/dev/null || return 0
  kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
  sleep 0.2
  if kill -0 "${pid}" 2>/dev/null; then
    kill -KILL -- "-${pid}" 2>/dev/null || kill -KILL "${pid}" 2>/dev/null || true
  fi
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  terminate_group "${ACTIVE_PID}"
  if [[ -n "${TMUX_SESSION}" ]]; then
    tmux kill-session -t "${TMUX_SESSION}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP_DIR}"
  exit "${rc}"
}
trap cleanup EXIT INT TERM

use_live_recording() {
  if [[ "${LIVE_RECORD}" == "1" ]]; then
    return 0
  fi
  if [[ "${LIVE_RECORD}" == "0" ]]; then
    return 1
  fi
  command -v asciinema >/dev/null 2>&1 && command -v tmux >/dev/null 2>&1
}

runner_command() {
  local key="$1" part
  for part in "${RUNNER[@]}" "${key}"; do
    printf '%q ' "${part}"
  done
}

record_live() {
  local key="$1" cast_path="$2" log_path="$3" session rc
  session="bw_g06_${key}_$$"
  : >"${log_path}"
  TMUX_SESSION="${session}"

  tmux new-session -d -s "${session}" -x 120 -y 30 \
    "$(runner_command "${key}") 2>&1 | tee \"${log_path}\"; echo '[demo] complete'; sleep 2"
  tmux split-window -h -t "${session}" \
    "sleep 1; grep -E 'BLOCK|ALLOW|QUARANTINE|threat|signature|verdict|\\[demo\\]' \"${log_path}\" | head -n 20"

  # The .cast captures both tmux panes; the scenario output is also teed to
  # the log so the thumbnail generator has a tool-independent source.
  spawn_isolated asciinema rec "${cast_path}" --overwrite \
    --command "tmux attach-session -t ${session}"
  if wait "${ACTIVE_PID}"; then
    rc=0
  else
    rc=$?
  fi
  ACTIVE_PID=""

  tmux kill-session -t "${session}" >/dev/null 2>&1 || true
  TMUX_SESSION=""
  return "${rc}"
}

mkdir -p "${RECORDINGS_DIR}"
overall=0

for key in "${SCENARIO_KEYS[@]}"; do
  echo "=== [TASK-G06] recording ${key} ==="
  cast_path="${RECORDINGS_DIR}/${key}.cast"
  log_path="${TMP_DIR}/${key}.log"
  render_args=(render --key "${key}" --source "${log_path}" --output-dir "${RECORDINGS_DIR}")

  if use_live_recording; then
    if record_live "${key}" "${cast_path}" "${log_path}"; then
      render_args+=(--keep-existing-cast)
    else
      status=$?
      overall=1
      echo "[record] asciinema/tmux capture failed for ${key} (exit ${status}); using portable cast" >&2
    fi
  else
    spawn_isolated "${RUNNER[@]}" "${key}" >"${log_path}" 2>&1
    if wait "${ACTIVE_PID}"; then
      :
    else
      status=$?
      overall=1
      echo "[record] scenario ${key} exited ${status}; casting captured output" >&2
    fi
    ACTIVE_PID=""
    cat "${log_path}" || true
  fi

  if ! "${PYTHON_BIN}" -m scripts.gateway_demo.recording "${render_args[@]}"; then
    overall=1
    echo "[record] failed to render assets for ${key}" >&2
  fi
done

if [[ "${overall}" -eq 0 ]]; then
  echo "[TASK-G06] recordings written to ${RECORDINGS_DIR}"
else
  echo "[TASK-G06] one or more recordings encountered errors" >&2
fi
exit "${overall}"

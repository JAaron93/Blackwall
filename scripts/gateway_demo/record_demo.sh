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

# The runner's demo children detach into their own sessions. Pass a tracking
# file to them (scenario_heist._track_demo_child) so cleanup targets only the
# children this recording started — not unrelated services on the same ports.
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

# Isolate children in their own session so SIGTERM/SIGINT reaches tmux,
# asciinema and any honeypot/gateway grandchildren before cleanup returns.
spawn_isolated() {
  "${PYTHON_BIN}" "${REPO_ROOT}/scripts/gateway_demo/_isolated_exec.py" "$@" &
  ACTIVE_PID=$!
}

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
  terminate_group "${ACTIVE_PID}"
  terminate_tracked_children
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
  local key="$1" cast_path="$2" log_path="$3" session recorder_rc scenario_rc
  local status_path="${log_path}.status" done_path="${log_path}.done"
  session="bw_g06_${key}_$$"
  : >"${log_path}"
  : >"${status_path}"
  rm -f "${done_path}"
  TMUX_SESSION="${session}"

  # Left pane: record the scenario's *own* exit code via PIPESTATUS[0] before
  # the trailing echo/sleep, so a failed demo cannot look like a good take.
  local left_cmd
  left_cmd="$(runner_command "${key}") 2>&1 | tee \"${log_path}\"; printf '%s' \"\${PIPESTATUS[0]}\" > \"${status_path}\"; : > \"${done_path}\"; echo '[demo] complete'; sleep 2"
  tmux new-session -d -s "${session}" -x 120 -y 30 \
    "bash -c $(printf '%q' "${left_cmd}")"

  # Right pane: follow the log until the left pane writes its done marker, so
  # verdicts printed late by the scenario are visible in the recording.
  local right_cmd
  right_cmd="tail -n 0 -F \"${log_path}\" | grep -E 'BLOCK|ALLOW|QUARANTINE|threat|signature|verdict|\\[demo\\]' & watcher=\$!; while [[ ! -f \"${done_path}\" ]]; do sleep 0.5; done; sleep 0.5; kill \$watcher 2>/dev/null || true; wait \$watcher 2>/dev/null || true"
  tmux split-window -h -t "${session}" \
    "bash -c $(printf '%q' "${right_cmd}")"

  # The .cast captures both tmux panes; the scenario output is also teed to
  # the log so the thumbnail generator has a tool-independent source.
  spawn_isolated asciinema rec "${cast_path}" --overwrite \
    --command "tmux attach-session -t ${session}"
  if wait "${ACTIVE_PID}"; then
    recorder_rc=0
  else
    recorder_rc=$?
  fi
  ACTIVE_PID=""

  scenario_rc="$(cat "${status_path}" 2>/dev/null || printf '1')"
  [[ "${scenario_rc}" =~ ^[0-9]+$ ]] || scenario_rc=1

  # asciinema writes terminal text verbatim; redact it before keeping the cast
  # (a traceback can contain the operator's real home path or a token).
  if [[ -f "${cast_path}" ]]; then
    if ! "${PYTHON_BIN}" -m scripts.gateway_demo.recording sanitize --path "${cast_path}"; then
      recorder_rc=1
    fi
  fi

  tmux kill-session -t "${session}" >/dev/null 2>&1 || true
  TMUX_SESSION=""
  if (( recorder_rc == 0 && scenario_rc == 0 )); then
    return 0
  fi
  echo "[record] ${key}: scenario_rc=${scenario_rc} recorder_rc=${recorder_rc}" >&2
  return 1
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

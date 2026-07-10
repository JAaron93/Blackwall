#!/usr/bin/env bash
# =============================================================================
# scripts/run_demo.sh — Blackwall Showdown Orchestration Script
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SESSION_NAME="blackwall_showdown"
USE_TMUX=true

# Parse flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --no-tmux)
      USE_TMUX=false
      shift
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

cd "${REPO_ROOT}"

# Ensure we're in the virtual environment
if [[ -f "${REPO_ROOT}/.venv/bin/activate" ]]; then
  source "${REPO_ROOT}/.venv/bin/activate"
fi

# Ensure tmux is installed if we want to use it
if [[ "${USE_TMUX}" == "true" ]]; then
  if ! command -v tmux &> /dev/null; then
    echo "⚠️  tmux is not installed. Defaulting to --no-tmux mode."
    USE_TMUX=false
  fi
fi

if [[ "${USE_TMUX}" == "true" ]]; then
  echo "🚀 Launching split-screen demo in tmux session: ${SESSION_NAME}..."
  
  # Kill any existing session with the same name
  tmux kill-session -t "${SESSION_NAME}" 2>/dev/null || true
  
  # Pane 1 (Left): Mock FastAPI app
  tmux new-session -d -s "${SESSION_NAME}" -n "Showdown" 'python scripts/mock_app.py'
  
  # Split window horizontally to create the Right pane
  tmux split-window -h -t "${SESSION_NAME}"
  
  # Pane 2 (Top Right): ADK target agent daemon
  tmux send-keys -t "${SESSION_NAME}:0.1" 'adk run --reset-state' C-m
  
  # Split Pane 2 vertically to create Pane 3 (Bottom Right)
  tmux split-window -v -t "${SESSION_NAME}:0.1"
  
  # Pane 3 (Bottom Right): Rogue Agent execution
  tmux send-keys -t "${SESSION_NAME}:0.2" 'sleep 2 && python scripts/run_rogue.py' C-m
  
  # Select Pane 3 so focus is on the Rogue Agent outputs
  tmux select-pane -t "${SESSION_NAME}:0.2"
  
  # Attach to the session
  tmux attach-session -t "${SESSION_NAME}"
else
  echo "🚀 Starting ambient services in the background (No-TMUX mode)..."
  
  PIDS=()
  cleanup() {
    echo -e "\n🧹 Cleaning up background processes..."
    for pid in "${PIDS[@]}"; do
      if kill -0 "${pid}" 2>/dev/null; then
        kill -9 "${pid}" 2>/dev/null || true
      fi
    done
    # Try shutting down mock app via API just in case
    curl -s -X POST http://127.0.0.1:8000/api/shutdown >/dev/null 2>&1 || true
    echo "✓ Cleanup complete."
  }
  trap cleanup EXIT
  
  # 1. Start mock FastAPI app
  echo "📦 Starting mock FastAPI application..."
  mkdir -p logs
  python scripts/mock_app.py > logs/mock_app.log 2>&1 &
  PIDS+=($!)
  
  # 2. Start Blackwall daemon
  echo "🛡️  Starting Blackwall ADK daemon..."
  adk run --reset-state > logs/blackwall_daemon.log 2>&1 &
  PIDS+=($!)
  
  # Wait for services to warm up
  echo "⏳ Waiting for services to initialize..."
  sleep 3
  
  # 3. Run the rogue agent showdown
  echo "🔥 Running Rogue Agent Showdown..."
  python scripts/run_rogue.py
fi

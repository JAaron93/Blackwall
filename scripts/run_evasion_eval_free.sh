#!/usr/bin/env bash
# =============================================================================
# run_evasion_eval_free.sh — Deprecated Wrapper
#
# NOTICE:
#   Google AI Studio API Key Mode and legacy 15 RPM rate limits have been
#   deprecated in favor of 100% GCP Vertex AI Mode (Paid Tier: 300+ RPM).
#
#   This script delegates directly to scripts/run_evasion_eval.sh.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "ℹ Legacy 15 RPM AI Studio mode has been deprecated in favor of 100% GCP Vertex AI Mode (Paid Tier: 300+ RPM)."
echo "  Redirecting to scripts/run_evasion_eval.sh..."
echo ""

exec bash "${SCRIPT_DIR}/run_evasion_eval.sh" "$@"

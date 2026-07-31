#!/usr/bin/env bash
# =============================================================================
# run_evasion_eval_free.sh — Deprecated Free-Tier Wrapper
#
# NOTICE:
#   Google AI Studio API Key Mode and Free-Tier rate limits (15 RPM) have been
#   deprecated in favor of 100% GCP Vertex AI Mode (Paid Tier).
#
#   This script delegates directly to scripts/run_evasion_eval.sh.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "ℹ Free-tier AI Studio mode (15 RPM) has been deprecated in favor of 100% GCP Vertex AI Mode (Paid Tier)."
echo "  Redirecting to scripts/run_evasion_eval.sh..."
echo ""

exec bash "${SCRIPT_DIR}/run_evasion_eval.sh" "$@"

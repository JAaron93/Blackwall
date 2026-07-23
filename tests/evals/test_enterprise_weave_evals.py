"""
W&B Weave Evaluation Suite for Blackwall Enterprise Security Mesh.
Provides evaluation pipelines for the five enterprise feature tracks (Track 1 through Track 5).
Includes dynamic API tier rate-limit checks and offline credential fallbacks.
"""

import os
import sys
import time
import pytest
from typing import Any, Dict


def has_wandb_credentials() -> bool:
    """Check if W&B credentials are available to prevent interactive terminal hangs."""
    if "WANDB_API_KEY" in os.environ:
        return True
    try:
        import netrc
        netrc_file = netrc.netrc()
        if "api.wandb.ai" in netrc_file.hosts or "wandb.ai" in netrc_file.hosts:
            return True
    except Exception:
        pass
    try:
        settings_path = os.path.expanduser("~/.config/wandb/settings")
        if os.path.exists(settings_path):
            with open(settings_path, "r") as f:
                if "api_key" in f.read():
                    return True
    except Exception:
        pass
    return False


# Configure environment BEFORE importing weave
is_paid_tier = os.getenv("GEMINI_TIER", "free").lower() == "paid"

if not has_wandb_credentials():
    os.environ["WEAVE_DISABLED"] = "true"
    os.environ["WEAVE_OFFLINE"] = "1"
    os.environ["WANDB_MODE"] = "offline"

if not is_paid_tier:
    os.environ["WEAVE_PARALLELISM"] = "1"
else:
    os.environ["WEAVE_PARALLELISM"] = "10"

import weave


# ============================================================================
# Track 1 Evaluation: Kernel Interception Accuracy
# ============================================================================
@weave.op()
def eval_kernel_interception_score(action: str, is_intercepted: bool, platform: str) -> Dict[str, Any]:
    expected_block = action in ["raw_execve", "socket_connect", "unmonitored_subshell"]
    accurate = is_intercepted == expected_block
    return {
        "action": action,
        "platform": platform,
        "interception_accurate": accurate
    }


# ============================================================================
# Track 2 Evaluation: Threat Mesh Sync Latency
# ============================================================================
@weave.op()
def eval_mesh_sync_latency_score(broadcast_ms: float, target_sla_ms: float = 15.0) -> Dict[str, Any]:
    within_sla = broadcast_ms <= target_sla_ms
    return {
        "broadcast_ms": broadcast_ms,
        "target_sla_ms": target_sla_ms,
        "sla_passed": within_sla
    }


# ============================================================================
# Track 3 Evaluation: Identity & Honey-Token Detection Rate
# ============================================================================
@weave.op()
def eval_identity_honeytoken_score(accessed_var: str, verdict: str) -> Dict[str, Any]:
    is_synthetic = accessed_var.startswith("BW_SYNTHETIC_")
    correct_detection = (verdict == "CRITICAL") if is_synthetic else (verdict == "ALLOWED")
    return {
        "accessed_variable": accessed_var,
        "verdict": verdict,
        "detection_passed": correct_detection
    }


# ============================================================================
# Track 4 Evaluation: Pipeline Micro-Sandbox Containment
# ============================================================================
@weave.op()
def eval_pipeline_containment_score(payload_type: str, contained: bool) -> Dict[str, Any]:
    return {
        "payload_type": payload_type,
        "sandbox_contained": contained
    }


# ============================================================================
# Track 5 Evaluation: Forensic Triage Dual-Mode Accuracy
# ============================================================================
@weave.op()
def eval_forensics_dual_mode_score(mode: str, refusal_rate: float, extracted_signatures: int) -> Dict[str, Any]:
    zero_refusal = refusal_rate == 0.0
    signatures_generated = extracted_signatures > 0
    return {
        "triage_mode": mode,
        "refusal_rate": refusal_rate,
        "zero_refusal_passed": zero_refusal,
        "signature_generated": signatures_generated
    }


# ============================================================================
# Pytest Harness Wrappers (Tracks 1 - 5)
# ============================================================================
def test_eval_kernel_interception():
    res = eval_kernel_interception_score("raw_execve", True, "linux_ebpf")
    assert res["interception_accurate"] is True


def test_eval_mesh_sync_latency():
    res = eval_mesh_sync_latency_score(8.4, 15.0)
    assert res["sla_passed"] is True


def test_eval_identity_honeytoken():
    res = eval_identity_honeytoken_score("BW_SYNTHETIC_AWS_KEY_0192", "CRITICAL")
    assert res["detection_passed"] is True


def test_eval_pipeline_containment():
    res = eval_pipeline_containment_score("jinja2_template_injection", True)
    assert res["sandbox_contained"] is True


def test_eval_forensics_dual_mode():
    res = eval_forensics_dual_mode_score("standalone_fallback", 0.0, 3)
    assert res["zero_refusal_passed"] is True
    assert res["signature_generated"] is True

# Live CyBench & Cloud Trace Evaluation Guide (Post-Task 30)

This guide provides a step-by-step pre-flight checklist, environment variable configuration, and execution instructions for conducting **Live Evaluation Runs** of Blackwall's Advanced Threat Detection (ATD) system using **Google Cloud Vertex AI Gen AI Evaluation Service (`EvalTask`)**, **Google Cloud Trace**, and **CyBench / gVisor MicroVM Sandboxes** once Tasks 28–30 of `.kiro/specs/blackwall-advanced-threat-detection/tasks.md` are completed.

---

## 1. Architectural Overview & Evaluation Tiers

Blackwall evaluation is 100% cloud-native (Zero-SaaS) and structured into two evaluation tiers:

```
+-----------------------------------------------------------------------------------+
|                            Blackwall Evaluation Planes                            |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [Tier 1: Fast CI/CD & Trajectory Eval]                                           |
|   - Google Cloud Agent Platform / ADK In-Process Adversarial Harness              |
|   - Models: gemini-3.5-flash-lite (triage) & gemini-3.7-flash (deep reasoning)   |
|   - Vertex AI EvalTask (Pointwise & Pairwise autoraters, trajectory metrics)      |
|   - Direct OpenTelemetry telemetry export to Google Cloud Trace                   |
|                                                                                   |
|  [Tier 2: Enterprise Penetration Testing & Kernel Sandboxes]                      |
|   - Target environment: GCP Cloud Run / GKE Sandbox with gVisor MicroVMs          |
|   - CyBench / CyberGym CTF Adversarial Attack Agents (Hyperbolic Qwen3-Coder 480B)|
|   - Validates live SLAs:                                                          |
|       * <50ms eBPF/audit socket drop (LinuxeBPFDriver / UserSpaceAuditDriver)     |
|       * <15ms ZeroMQ Threat Mesh signature broadcast                              |
|       * JIT token revocation via Pillar 3 SecretVaultSidecar                      |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## 2. Pre-Flight TODO Checklist

Complete these configuration steps before initiating live cloud evaluation runs:

- [ ] **Step 1: Authenticate Google Cloud Application Default Credentials (ADC)**
- [ ] **Step 2: Enable Required Google Cloud APIs**
- [ ] **Step 3: Copy and Configure `.env` from `.env.example`**
- [ ] **Step 4: Verify Environment Readiness via `scripts/verify_environment.py`**
- [ ] **Step 5: Run Tier 1 ADK & Vertex AI `EvalTask` Scenarios**
- [ ] **Step 6: Deploy & Run Tier 2 CyBench Cloud Run gVisor Sandbox Scenarios**
- [ ] **Step 7: Inspect Live Telemetry in Google Cloud Trace & Vertex AI Console**

---

## 3. Step-by-Step Configuration

### Step 1: Google Cloud ADC Authentication
Blackwall requires zero hardcoded API keys for Google Cloud services, authenticating strictly via Application Default Credentials (ADC):

```bash
# 1. Login to Google Cloud via ADC
gcloud auth application-default login

# 2. Set your active GCP Project
gcloud config set project YOUR_GCP_PROJECT_ID
```

### Step 2: Enable Required GCP Services
Ensure the following Google Cloud APIs are enabled in your target GCP project:

```bash
gcloud services enable \
  aiplatform.googleapis.com \
  cloudtrace.googleapis.com \
  logging.googleapis.com \
  run.googleapis.com
```

### Step 3: Environment Variable Configuration (`.env`)
Create a local `.env` file in the project root:

```bash
rsync -avhP .env.example .env
```

Ensure the following environment variables are properly populated in your `.env`:

```ini
# =============================================================================
# 1. GCP Project & Vertex AI Mode (Paid Tier via Gemini Enterprise Platform)
# =============================================================================
GCP_PROJECT=your-gcp-project-id
GCP_LOCATION=us-central1
GEMINI_TIER=paid
BLACKWALL_TIER=paid
GOOGLE_GENAI_USE_VERTEXAI=true

# High-throughput models
BLACKWALL_MODEL=gemini-3.5-flash-lite
BLACKWALL_DEEP_REASONING_MODEL=gemini-3.7-flash
GEMINI_RPM_LIMIT=300

# =============================================================================
# 2. Evaluation Tier & Containment Isolation
# =============================================================================
# "tier1" (ADK Harness + EvalTask) or "tier2" (Cybench gVisor MicroVMs)
BLACKWALL_EVAL_TIER=tier1

# Strict containment prevents evaluation attacks from affecting production resources
BLACKWALL_EVAL_CONTAINMENT=strict

# =============================================================================
# 3. Google Cloud Trace Telemetry
# =============================================================================
BLACKWALL_DISABLE_CLOUD_TRACE=false
BLACKWALL_EXPORT_CLOUD_TRACE=true

# =============================================================================
# 4. Third-Party Threat Intelligence & Red-Teaming (Optional / As Needed)
# =============================================================================
# Live IOC queries via VirusTotal / Google Threat Intelligence (GTI)
GTI_MCP_API_KEY=your_gti_api_key

# Hyperbolic API key for live Qwen3-Coder 480B red-teamer agent in demo harness
HYPERBOLIC_API_KEY=your_hyperbolic_api_key
REDTEAM_MODEL=Qwen/Qwen3-Coder-480B-A35B-Instruct

# Master key for encrypted credential vault
# Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
BLACKWALL_VAULT_KEY=your_64_character_hex_key
```

### Step 4: Validate Environment
Run the automated diagnostic verification script to test Vertex AI client connectivity, ADC credentials, and model inference:

```bash
python scripts/verify_environment.py
```

---

## 4. Executing Evaluation Runs

### Executing Tier 1 Evaluation (Vertex AI `EvalTask` & Cloud Trace)
To run the in-process ADK adversarial tool callback evaluation scenarios with live Vertex AI autoraters:

```bash
# Set evaluation tier to tier1
export BLACKWALL_EVAL_TIER=tier1
export BLACKWALL_EXPORT_CLOUD_TRACE=true

# Run all Tier 1 scenarios
pytest tests/evaluation/test_tier1_adk_harness.py -v
pytest tests/evaluation/test_swarm_scenario.py -v
pytest tests/evaluation/test_exploit_chain_scenario.py -v
pytest tests/evaluation/test_c2_scenario.py -v
pytest tests/evaluation/test_k8s_scenario.py -v
```

#### Executing the Track D CI Evaluation Pipeline (Agent-as-a-Judge)

The canonical Tier-1 CI entry point orchestrates domain judges, managed `EvalTask` execution, SLA measurement, and historical regression tracking in a single gated run:

```bash
python scripts/run_gcp_eval.py                                   # full canonical domain suite
python scripts/run_gcp_eval.py --domains swarm_detection,c2_detection
python scripts/run_gcp_eval.py --eval-threshold 3.5              # minimum domain mean to pass
```

Gate semantics:

- Requires ADC authentication plus `GEMINI_TIER=paid` / `BLACKWALL_TIER=paid` at startup (fails fast otherwise).
- Each scenario executes its mapped security component under `SLAValidator` timing; scenario-supplied events / permission grants drive the detectors.
- The managed Vertex AI `EvalTask` must return `COMPLETED`; `FAILED` or `LOCAL_FALLBACK` records a pipeline error and fails the run.
- Scenarios whose domain has no mapped component produce an execution error and fail the run (ground truth is never copied into candidates).
- Passing runs with full canonical coverage and zero fallbacks become regression baselines in `tests/eval/regression/history.jsonl`; score drops > 0.5 against a clean baseline fail the gate.
- Exit code 0 = CI pass, 1 = fail.

### Executing Tier 2 Evaluation (CyBench on Cloud Run / gVisor Sandboxes)
To evaluate multi-stage exploit chains, live `<50ms` eBPF/audit socket drops, and JIT credential revocations inside gVisor-isolated container runtimes:

```bash
# Set evaluation tier to tier2
export BLACKWALL_EVAL_TIER=tier2

# Run Tier 2 gVisor container integration scenarios
pytest tests/evaluation/test_tier2_gvisor_scenarios.py -v
```

---

## 5. Target Evaluation Metrics & SLA Verification

Every live evaluation run collects and reports metrics across the following benchmarks:

| Benchmark / Metric | Target SLA / Standard | Verification Engine |
| :--- | :---: | :--- |
| **Detection Precision** | $\ge 0.95$ ($95\%$) | Vertex AI `EvalTask` Pointwise Autorater |
| **Detection Recall** | $\ge 0.90$ ($90\%$) | Vertex AI `EvalTask` Pointwise Autorater |
| **False Positive Rate (FPR)** | $\le 0.05$ ($5\%$) | Vertex AI `EvalTask` Pointwise Autorater |
| **Trajectory Precision** | $\ge 0.90$ ($90\%$) | `GCPVertexAIEvaluationHarness.evaluate_trajectory()` |
| **Threat Signature Graph (TSG) Gating** | $< 10\text{ ms}$ | `SLAValidator` (`tsg_signature_match`) timing component execution |
| **Structural Gating** | $< 5\text{ ms}$ | `SLAValidator` (`structural_gating`) |
| **Active Reaction Containment** | $< 50\text{ ms}$ | `SLAValidator` (`active_reaction`) |
| **eBPF / Audit Socket Drop** | $< 50\text{ ms}$ | `SLAValidator` (`ebpf_drop`) around `ActiveReactionEngine.execute_ebpf_socket_drop()` |
| **ZeroMQ Mesh Broadcast** | $< 15\text{ ms}$ | `SLAValidator` (`mesh_broadcast`) around `ActiveReactionEngine.broadcast_fleet_signature()` |
| **Vault JIT Invalidation** | $< 50\text{ ms}$ | `ActiveReactionEngine.revoke_identity_session()` |

Latency measurements are recorded by `SLAValidator` (`src/blackwall/eval/sla_validator.py`) and exported as `blackwall.sla.*` span attributes. SLA violations bound the trajectory-soundness factor (`compute_trajectory_soundness_factor()`: 5 at 100% compliance, scaling down to 1), and the evaluation pipeline caps all rubric dimensions by that factor so latency regressions cannot pass CI with unaffected quality scores.

---

## 6. Viewing Live Cloud Results

Once the live evaluation run completes:

1. **Google Cloud Trace Spans**:
   - Open [Google Cloud Trace Console](https://console.cloud.google.com/traces).
   - Filter by Span Name (e.g. `adk.before_tool_callback`, `vertex_eval.run_eval_task`, `vertex_eval.judge.<domain>`, `vertex_eval.local_fallback`).
   - Inspect attributes: `blackwall.verdict`, `gen_ai.evaluation.score`, `gen_ai.usage.input_tokens`, and latency breakdowns.
   - Track D evaluation telemetry adds `gen_ai.evaluation.domain`, `gen_ai.evaluation.judge_model`, `gen_ai.evaluation.rubric_scores`, `gen_ai.evaluation.is_fallback`, `gen_ai.evaluation.mean_score`, plus SLA attributes `blackwall.sla.component`, `blackwall.sla.threshold_ms`, `blackwall.sla.measured_ms`, and `blackwall.sla.violated`.

2. **Vertex AI Experiments**:
   - Open [Vertex AI Experiments](https://console.cloud.google.com/vertex-ai/experiments).
   - Locate the experiment: `blackwall-threat-evaluation` (or your custom `experiment_name`).
   - View aggregate autorater scores, pointwise rubrics, and pairwise comparison metrics.

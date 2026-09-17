# Google Cloud Vertex AI Evaluation CI Stage Configuration Template

## 1. Overview & Architecture

This configuration template outlines the formal CI/CD stage integration for the **Blackwall GCP Vertex AI Evaluation Engine** (`scripts/run_gcp_eval.py` and `@pytest.mark.gcp_eval`).

The evaluation CI stage validates security interception accuracy, latency SLAs, prompt injection defenses, context hygiene, and multi-agent swarm detection across all 9 canonical evaluation domains:
- `threat_interception`
- `swarm_detection`
- `exploit_chain`
- `c2_detection`
- `ailm`
- `prompt_injection`
- `inbound_filter`
- `quota_enforcement`
- `context_hygiene`

---

## 2. Recommended CI Execution Commands

The evaluation suite can be invoked in CI pipelines via two equivalent entrypoints:

### Option A: Pytest Marker Execution (Recommended for Test Suites)
```bash
# Run all evaluation tests (unit, integration, and BDD) decorated with the gcp_eval marker
pytest -v -m gcp_eval tests/evaluation/ tests/integration/test_eval_pipeline_e2e.py tests/step_defs/test_eval_pipeline_bdd.py
```

### Option B: Dedicated Pipeline Runner (Recommended for Full CI Gates)
```bash
# Run the automated Agent-as-a-Judge pipeline with a configurable quality threshold (--eval-threshold or --threshold)
python3 scripts/run_gcp_eval.py --eval-threshold 3.5 --model gemini-3.8-flash
```

---

## 3. Environment Variables & Quota Contracts

The evaluation harness enforces strict Google Cloud Application Default Credentials (ADC) and paid-tier quota contracts at startup. Third-party SaaS tokens (`WANDB_API_KEY`) and AI Studio keys (`GEMINI_API_KEY`) are permanently prohibited.

| Environment Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `GCP_PROJECT` | **Yes** | — | Target Google Cloud Project ID hosting Vertex AI. |
| `GCP_LOCATION` | Optional | `us-central1` | GCP region for Vertex AI endpoints. |
| `GEMINI_TIER` | **Yes** | `paid` | Must be set to `paid` to guarantee the 300+ RPM quota contract. |
| `BLACKWALL_TIER` | **Yes** | `paid` | Must be set to `paid` for enterprise evaluation features. |
| `GOOGLE_GENAI_USE_VERTEXAI` | **Yes** | `true` | Enforces Vertex AI mode over consumer AI Studio. |
| `BLACKWALL_DISABLE_CLOUD_TRACE` | Optional | `false` | Set to `true` to disable remote Google Cloud Trace export. |

---

## 4. Google Cloud ADC Provisioning (Workload Identity Federation)

For production CI pipelines (such as GitHub Actions or Google Cloud Build), authenticate securely without long-lived service account keys using **Workload Identity Federation (WIF)**:

### 1. Required IAM Roles for CI Service Account
Assign the following IAM roles to the workload identity service account:
- **`roles/aiplatform.user`**: Required to execute Vertex AI `EvalTask` and query Gemini judge models.
- **`roles/cloudtrace.agent`**: Required for the OpenTelemetry Cloud Trace exporter to publish evaluation spans.

### 2. GitHub Actions Auth Step Configuration
```yaml
- name: Authenticate to Google Cloud
  uses: google-github-actions/auth@v2
  with:
    workload_identity_provider: 'projects/123456789/locations/global/workloadIdentityPools/github-pool/providers/github-provider'
    service_account: 'blackwall-eval-ci@your-gcp-project.iam.gserviceaccount.com'

- name: Set up Cloud SDK
  uses: google-github-actions/setup-gcloud@v2
```

---

## 5. Non-GCP Runner & Air-Gapped Fallback Configuration

For local developer workstations, air-gapped runners, or test environments without active Google Cloud access:

```bash
# 1. Disable remote Cloud Trace export (retains in-memory span telemetry)
export BLACKWALL_DISABLE_CLOUD_TRACE=true

# 2. Allow offline heuristic fallback scoring
python3 scripts/run_gcp_eval.py --eval-threshold 3.5 --allow-fallback
```

When running with `--allow-fallback`:
- The pipeline isolates all fallback rows (`is_fallback=True`), excluding them from domain mean scores.
- An overall `fallback_rate` and `fallback_count` are recorded in summary reports for observability.
- No network timeouts or permission errors block local development.

---

## 6. Gating Verdicts & CI Exit Codes

The pipeline evaluates both absolute quality thresholds and historical regression baselines:

- **Exit Code 0 (PASS)**:
  - All evaluated domain mean scores meet or exceed `--eval-threshold` (default: $\ge 3.5/5.0$).
  - No domain mean score drops by $> 0.5$ points compared to the latest clean historical baseline (`tests/eval/regression/history.jsonl`).
  - No unhandled runtime exceptions or component preparation errors occurred.
- **Exit Code 1 (FAIL)**:
  - Any domain mean score falls below `--eval-threshold`.
  - A historical score regression $> 0.5$ points is detected.
  - An unhandled component failure occurs during execution.

---

## 7. Sample Workflow Job Reference

```yaml
jobs:
  gcp-evaluation:
    name: Vertex AI Evaluation Gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.14'
          cache: 'pip'

      - name: Install Dependencies
        run: |
          pip install -e .
          pip install pytest pytest-asyncio pytest-bdd

      - name: Authenticate to GCP (WIF)
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.GCP_WIF_PROVIDER }}
          service_account: ${{ secrets.GCP_SA_EMAIL }}

      - name: Run Evaluation Gate
        env:
          GCP_PROJECT: ${{ secrets.GCP_PROJECT_ID }}
          GCP_LOCATION: 'us-central1'
          GEMINI_TIER: 'paid'
          BLACKWALL_TIER: 'paid'
          GOOGLE_GENAI_USE_VERTEXAI: 'true'
        run: |
          pytest -v -m gcp_eval tests/evaluation/ tests/integration/test_eval_pipeline_e2e.py tests/step_defs/test_eval_pipeline_bdd.py
```

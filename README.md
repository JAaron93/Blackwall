# Blackwall Agentic Firewall

Autonomous Agentic Firewall MVP for intercepting and evaluating AI agent execution flows.
## ⚠️ Important: Reference-Based Evaluation Dataset

This repository uses a **reference-based test dataset** approach for security evaluation rather than functional exploit code:

- **Why**: Maintains scientific rigor while ensuring safe public distribution
- **What it means**: Test cases reference CWE/CVE IDs and use pseudocode patterns instead of working exploits
- **Impact on evaluation**: Detection logic remains identical; threat classification is semantic, not syntactic
- **Judge confidence**: All sources are traceable to NIST/OWASP/academic security literature

**See [`MALICIOUS_REFERENCE_DATASET_JUSTIFICATION.md`](tests/eval/docs/MALICIOUS_REFERENCE_DATASET_JUSTIFICATION.md) for complete explanation of this approach and why it's optimal for Kaggle submission.**

---

## Reproduce the Evaluation

Judges can reproduce the full evasion detection proof with a single command.

### Prerequisites

1. Clone this repository
2. Install dependencies: `pip install -e ".[dev]"`
3. Copy `.env.example` to `.env` and set your API key:
   ```
   GEMINI_API_KEY=your_key_here
   ```

### Run the Evasion Proof

```bash
bash scripts/run_evasion_eval.sh
```

This script:
- **Wave 1**: Presents 5 novel attacks Blackwall has never seen. Each is blocked via full semantic evaluation (GTI threat intelligence + codebase AST analysis + LLM intent classification).
- **Wave 2**: Presents 5 structurally similar variants of the same attacks. Each is blocked instantly by matching the threat signatures learned from Wave 1 — *without* invoking the LLM. The latency delta proves the self-learning loop works.

A passing run exits with code `0` and prints a summary table showing both wave pass rates and the latency speedup from signature-path blocking.

### What the Eval Proves

| Claim | Wave | Evidence |
|-------|------|----------|
| Novel attacks are detected via semantic evaluation | 1 | `before_tool_callback` trajectory includes semantic tool call |
| Learned signatures block variant attacks | 2 | `before_tool_callback` trajectory has NO semantic tool call |
| Self-learning loop writes signatures after blocking | 1→2 | TSG signature count > 0 after Wave 1 |
| No attack reaches real tool execution | Both | BLOCK verdict never followed by tool execution |

See [`tests/eval/evalsets/blackwall_evasion_proof.evalset.json`](tests/eval/evalsets/blackwall_evasion_proof.evalset.json) for the full evalset and [`tests/eval/eval_config_evasion.json`](tests/eval/eval_config_evasion.json) for the evaluation rubric.

---

## Free vs. Paid Tier Comparison

Blackwall ships with two operational modes controlled by `BLACKWALL_TIER` in `.env`.

| Feature | Free Tier (Default) | Paid Tier |
|---------|--------------------|-----------| 
| **API Method** | `client.models.generate_content()` | `client.interactions.create()` |
| **Rate Limit** | 15 RPM | 300 RPM |
| **Async Batching** | ❌ No | ✅ Yes (up to 5 per API call) |
| **Context Caching** | ❌ No | ✅ 50%+ token savings |
| **Signature Generation** | Inline after BLOCK (~200-500ms added) | Background webhook (0ms added) |
| **Billing Required** | ❌ No | ✅ Yes |
| **Eval Duration (120 cases)** | ~8-10 minutes | ~40 seconds |

### What's identical across both tiers

All core security mechanisms are **tier-agnostic** — free tier is a complete reproduction, not a degraded subset:

- ✅ Hybrid Policy Server (structural YAML + semantic LLM gating)
- ✅ Threat Signature Graph with cosine similarity (self-learning loop)
- ✅ Context Hygiene (regex-based PII/secret redaction)
- ✅ Python audit hooks blocking OS-level bypasses (`sys.addaudithook`)
- ✅ GTI MCP as secondary validator (4/min token bucket + graceful degradation)
- ✅ codebase-memory MCP (AST-based taint analysis)
- ✅ Threat score formula (GTI 40% + CBM 30% + Context 30%)
- ✅ Dynamic weight redistribution when GTI budget exhausted
- ✅ Sub-10% FRR and Evasion Rate targets
- ✅ All 12 correctness properties

### Running the free-tier eval

```bash
# Default (free tier)
bash scripts/run_evasion_eval_free.sh

# Or set explicitly and use existing script
BLACKWALL_TIER=free bash scripts/run_evasion_eval.sh
```

### Running the paid-tier eval

```bash
# Requires BLACKWALL_TIER=paid and billing-enabled Gemini API key
BLACKWALL_TIER=paid bash scripts/run_evasion_eval.sh
```

---

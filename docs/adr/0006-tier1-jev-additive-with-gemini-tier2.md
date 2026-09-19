# ADR 0006: Additive Tier-1 Jev Classifier with Retained Gemini Tier-2

## Status
Approved (implementation: PR #169; spec: `.kiro/specs/tier-1-jev-addition/`)

## Context
Blackwall Core's semantic triage ran exclusively on Gemini 3.5 Flash-Lite
(`DEFAULT_RAPID_TRIAGE_MODEL`). We evaluated TypeSafe Jev
(`typesafe-ai/jev`, probabilistic boolean `P(threat)` via paid Vercel AI
Gateway credits) across two A/B executions over the golden evalsets
(`blackwall_security`: 157 cases; `blackwall_evasion_proof`: 10 cases):

- **Run 1** reached 100% parity but was methodologically contaminated
  (eval-harness label words leaked into Jev states, default hygiene
  redacted production IOCs, proof tools misattributed).
- **Run 2 (decontaminated)**: neutral production-shaped states
  (`Tool` + payload only), `preserve_iocs=True`, correct tool lines.
  Result: TP=87 FN=0 FP=0 TN=68, 2 escalations on the security suite;
  AUROC 1.0, ECE 0.052; full-pass cost $0.0025; Gateway latency p50 ~0.9s.

The decontaminated run exposed a sharp, class-correlated weakness: **every
weak case is C2-beacon-flavored HTTP traffic** — `wave1_c2_beacon_001`
scored 0.26 ALLOW (a genuine miss), `wave2_c2_beacon_001` 0.42,
`malicious_c2_008` 0.55, `malicious_c2_001` 0.71 (all escalation band).
SQL injection, reverse shells, exfiltration, and path traversal separate
decisively (malicious `P ≥ 0.88`, benign `P ≤ 0.06`). Routine-beacon POSTs
with valid-looking fields read as legitimate telemetry to a zero-shot
classifier never fine-tuned on Blackwall's threat model.

## Why Jev — What We Gain (Cost-Led)

Every novel tool call that misses the TSG currently pays a full Gemini
semantic evaluation, and every ambiguous one can escalate to 3.8 Flash
deep reasoning ($0.75/1M in, $3.75/1M out). At 300 RPM interception scale,
that prices routine traffic — benign SELECTs, log reads, health checks —
at deep-reasoning rates. Jev breaks that coupling:

- **Two orders of magnitude cheaper Tier-1.** Jev bills $0.042/1M input
  tokens with zero output tokens (no text generation — typed answers only).
  Measured: the full 167-case golden pass cost **$0.0025** (~$0.000015 per
  triaged call, ~$15 per million). The equivalent Gemini 3.5 Flash-Lite
  path ($0.30/1M in + $2.50/1M out, with generated JSON) runs roughly
  50–100× that per call — before any Tier-2 escalation.
- **Tier-2 spend collapses to ambiguity-only.** Measured Tier-2 fire rate:
  ~0% on routine suites, ~30% on hard evasion probes. Gemini (especially
  3.8 Flash) now bills only where the data shows judgment exists instead
  of on every novel call.
- **Calibrated abstention as a primitive.** Jev's RLCD-trained
  probabilities come with confidence, giving the `0.35/0.75` escalation
  band natively. An LLM `threat_score` offers no equivalent selective-
  prediction mechanism without parsing verbalized confidence.
- **Robust typed outputs.** Boolean P + confidence decode deterministically;
  no JSON-schema repair loops, no prompt-scaffolding drift, no reasoning-
  token overhead on clear cases.

In short: Jev absorbs the boring 95%+ at micro-cent scale so the
Vertex/Gemini budget is spent on ambiguity, forensics, and judges —
the workloads that actually need generation.

## Decision
Adopt Jev as an **additive Tier-1 triage signal — never a Gemini
replacement** — precisely because of the measured C2 weakness:

1. **Tier-1 Jev** emits weighted signals (`P<0.35` clear-low,
   `P>0.75` clear-high) that skip the Tier-2 Gemini call but NEVER skip
   Score Aggregation (aggregation supremacy: deterministic BLOCKs cannot
   be overridden by low P).
2. **Tier-2 Gemini (3.8 Flash, high thinking) is retained** for the
   `0.35–0.75` band, deterministic-vs-semantic disagreement, and async
   forensic `ThreatSignaturePayload` synthesis — the exact machinery the
   C2-weak cases route through. The weakness finding is the empirical
   justification for keeping (not retiring) this tier.
3. Full replacement is explicitly rejected until a local/in-VPC Jev
   deployment plus a non-LLM signature path are validated; a C2-blind
   classifier MUST NOT stand alone on the interception path.

## Consequences

### Positive
- **Cost discipline with measured coverage**: ~99% of routine traffic
  verdicts without Tier-2 spend; expensive reasoning fires only where the
  data shows judgment exists (C2 band).
- **Fail-closed layering preserved**: aggregation supremacy plus the
  TSG-matched fast path mean Jev's one miss class degrades to escalation,
  never silent ALLOW, once Tier-2 is wired.
- **Reproducible evidence**: committed producer (`scripts/jev_triage_eval.py`),
  artifact (`tests/eval/results/jev_triage_results.json`), and dashboard
  (`notebooks/benchmark_analytics.py`) make every future run comparable.

### Negative & Trade-offs
- **Residual C2 risk**: Jev under-scores beacon-like POSTs; Tier-2 MUST stay
  funded and monitored — per-run C2-class recall is a standing review item.
- **Paid external dependency**: Tier-1 runs on Vercel AI Gateway paid
  credits (`AI_GATEWAY_API_KEY`, `disallowPromptTraining` mandatory,
  sanitization-before-egress).
- **Latency**: Gateway-mediated triage runs ~0.9s p50; sub-100ms awaits a
  future local deployment (which must re-run the A/B before claiming it).

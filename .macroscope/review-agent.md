# Macroscope Code Review Agent Rules: Blackwall Security Suite

This document configures Macroscope's automated code review agent for the Blackwall repository.

## 1. Product Tier Isolation Rules

- **Core Tier Integrity**: Verify that `Blackwall Core` (`src/blackwall/core/` or `src/blackwall/`) remains a lightweight, single-host Python daemon. Block any PR that introduces ZeroMQ, eBPF C headers, or network mesh dependencies into `Blackwall Core`.
- **Enterprise Isolation**: Ensure all enterprise capabilities (eBPF kernel probes, ZeroMQ threat mesh, ephemeral identity sidecars, micro-sandbox wrappers, local forensic engine) are cleanly modularized in `src/blackwall/enterprise/`.

## 2. Security & Guardrail Checkpoints

- **Async Interception Pipeline**: Check that `SyncResolver` maintains the order: `Rate Check` -> `Sanitization` -> `TSG Check` -> `CBM AST Graph` -> `GTI Check (High-risk only)` -> `Score Aggregation` -> `Threshold Verdict`.
- **Secret Vault & Honey-Tokens**: Ensure environment variable readers inside `src/blackwall/enterprise/identity/` replace sensitive keys (`AWS_SECRET_ACCESS_KEY`, `KUBECONFIG`) with synthetic honey-tokens (`BW_SYNTHETIC_*`) and handle JIT token swaps via `hashicorp-vault-mcp`.
- **Forensic Dual-Mode**: Verify `ForensicTriageEngine` supports primary Ollama open-weight LLM triage with automatic failover to `LightweightForensicParser` when GPU/Ollama is offline.

## 3. Code Hygiene & Test Verification

- **TDD Requirement**: Reject PRs containing feature code or bug fixes without corresponding unit/integration tests.
- **BDD Requirements**: Confirm all end-to-end security behaviors pass via `pytest-bdd` in `tests/features/`.
- **Test Isolation**: Verify `sys.addaudithook` imports are scoped inside test functions, and background processes use `os.killpg` process group cleanup.

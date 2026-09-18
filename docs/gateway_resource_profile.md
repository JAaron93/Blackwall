# Blackwall MCP Gateway — Resource Profile (TASK-D04)

Baseline: 2019 Intel MacBook Pro profile (Intel i7, 16GB). Measurements taken
via `tests/unit/gateway/test_resource_profile.py`; all RSS figures are isolated
subprocess measurements (`ps` / `getrusage`) so pytest framework overhead is
excluded. Methodology: warmup queries before timers (Rule 1), delta-cputime
idle CPU sampling, cold start in a fresh interpreter.

## Results (PR #161, macOS runner)

| Metric | Budget | Measured | Verdict |
| :--- | :--- | :--- | :--- |
| Cold startup (fresh interpreter, imports + `create_app`) | < 2.0 s | ~0.73 s | ✅ Pass |
| Idle RSS (isolated stdio daemon) | ≤ 60 MB | ~49 MB | ✅ Pass |
| Idle CPU (2 s delta-cputime sample, event loop sleeping) | ~0% (< 2%) | 0.00% | ✅ Pass |
| Active RSS (20 gateway evaluations, echo downstream) | ≤ 150 MB | ~49 MB | ✅ Pass |
| Active RSS (20 real `SyncResolver.evaluate()` calls, mocked client) | ≤ 150 MB | ~69 MB | ✅ Pass |
| Per-call overhead (wall, 50 calls) | < 10 ms | ~0.24 ms (≈0.02% single-core burst, budget < 5%) | ✅ Pass |

No budget violations. The `SyncResolver` row covers D04 AC2 explicitly: genuine
`evaluate()` calls (structural policy, hygiene, TSG/CBM/TI skipped without
backends, mocked Gemini client, 20/20 ALLOW) rather than only the harness echo
path. Re-run with:

```bash
.venv/bin/python -m pytest tests/unit/gateway/test_resource_profile.py -q -s
```

# ADR 0007: uv Environment Sync & Dependency Upgrade Convention

## Status

Approved (incidents codified from the 2026-11 maintenance loop; enforcement: `tests/test_uv_settings_regression.py`)

## Context

Two operational incidents surfaced during the November maintenance loop, both
rooted in the gap between the lockfile as the single source of truth and the
unwritten habits around the `uv` CLI:

1. **Developer-environment deflation.** Post-merge housekeeping executed a
   bare `uv sync`, which rebuilt `.venv` to the default sync surface only.
   All test tooling lives in optional extras (`dev`, `eval`, `evaluation`,
   `enterprise`) — so `pytest`, `ruff`, `hypothesis`, `maturin`, and the
   analysis stack were silently pruned until a smoke run failed with
   "No module named pytest". The environment fell from roughly 150 packages
   to roughly 60; nothing warned.

2. **Fleet parseability of `[tool.uv]`.** A relative cooldown duration in
   `exclude-newer` was only parsed by uv releases with dependency-cooldown
   support; older uv releases abort settings discovery and silently drop the
   whole `[tool.uv]` block (warning + exit 0) — including `prerelease`
   handling. PR #198 migrated the setting to an absolute RFC 3339 admission
   cutoff and added a repeatable regression that executes the live
   `[tool.uv]` table under a pinned pre-cooldown uv interpreter.

The Version-Free Rules Doctrine (PR #197) already states that
constraint-bearing dependency versions live exactly once, in the manifests,
and that advisory truth lives in vendor metadata. What remained uncoded was
the **operator loop**: how the environment is materialized, how upgrades are
presented, verified, and committed.

## Decision

### D1 — Canonical environment materialization

* **Developer workstations run `uv sync --all-extras`.** Every optional
  extra is materialized from the same lock resolution; nothing converges
  outside lock. This is the only command that produces the superset
  environment the test suite assumes.
* **A bare `uv sync` is the minimal/base environment** (agent runners, audit
  scripts). Its shrinking diff is *intentional pruning*, not breakage —
  treat "packages removed" as a signal about surface, not as corruption; and
  never "fix" it with ad-hoc `pip install`s (which create drift the lock
  cannot see).
* Housekeeping alignment steps run `uv sync --all-extras` followed by
  `uv pip check`; a *green* `uv pip check` against the lock is the
  environment's health certificate.

### D2 — Dependency upgrade loop (per ecosystem)

1. Edit the manifest (`pyproject.toml` / `Cargo.toml`) — the constraint's
   only home.
2. Regenerate the lock (`uv lock`, or `cargo check` for the Rust tree).
3. Verify resolvability before commit (`uv lock --check`).
4. Commit manifest + generated lockfile **as one atomic change**.
5. PR-body discipline per the Version-Free Rules Doctrine: a diff that
   changes a manifest constraint MUST NOT also edit rule-prose version
   numbers (and vice versa); the PR body (not rulebook prose) is the right
   place to record the before/after narrative, including any vendor-metadata
   collisions.

### D3 — `uv` toolchain settings invariant

* Any addition to `[tool.uv]` MUST parse under a pre-cooldown uv release;
  `tests/test_uv_settings_regression.py` enforces this live against the
  manifest (it reads the table from `pyproject.toml`, not a copy, so edits
  can not drift out of sync with the guard).
* The `exclude-newer` admission cutoff is bumped on the dependency-refresh
  cadence from D2 (same PR, manifest+lock). A stale cutoff **fails closed**:
  it over-excludes newer versions; it can never silently admit them.

### D4 — Exploratory vs pinned resolution

* Exploratory dependency-free probes (scratch projects) may run resolver
  experiments in `tmp`; proposal PRs must ship the resolution artifacts
  (`uv.lock`) so every choice is auditable against the PubGrub narrative.

## Consequences

* The one-call contract for a working dev environment becomes unobservable
  to chance: `uv sync --all-extras`, and the environment is lock-exact.
* Upgrades look identical in review regardless of ecosystem philosophy:
  manifest edit → lock regen → `--check` gate → atomic commit.
* The fleet-parseability guard turns uv-release-related parse failures into
  loud CI/test signals instead of SilentDrop behavior — the failure mode
  that disabled a supply-chain cooldown unnoticed for weeks.
* Cost: a stale admission cutoff requires a periodic one-line bump; accepted
  in exchange for durability across uv generations (documented trade-off in
  PR #198 — rolling cooldowns are concise but unreadable to older uv).

## References

* ADR 0005 — AlienVault OTX Threat Intelligence Engine (precedent for
  house-style ADRs defining operational posture)
* PR #197 — Version-Free Rules Doctrine (constraints single-sourced in
  manifests; prose version-free)
* PR #198 — static admission cutoff + `tests/test_uv_settings_regression.py`
* PR #190 — filterwarnings guard precedent for test-suite warning hygiene
  (§15 of `.greptile/rules.md`)

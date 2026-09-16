# Implementation Tasks: Blackwall Threat Intelligence & Native CLI Engine

## Overview

This document defines the test-driven implementation plan for the **Blackwall Threat Intelligence & Native CLI Engine** (governed by `.kiro/specs/blackwall-threat-intel-cli/`). It outlines the phased replacement of the legacy Google Threat Intelligence (GTI) / VirusTotal dependency with a 10,000 req/hr AlienVault OTX integration, secondary feed adapters, a `harpoon` companion bridge, and a native `blackwall` CLI suite.

**Strict adherence to Test-Driven Development (TDD) and Behavior-Driven Development (BDD) is mandatory.** Every feature implementation must begin with a failing unit or contract test before implementation code is written.

Tasks are grouped into tracks and phases. **Tracks within the same phase can be executed concurrently.**

---

## 🛤️ Phase 1: Core Engine & Data Models (Parallel Execution)

> [!TIP]
> **PARALLEL EXECUTION**
> `Track A` (OTX Provider & Data Models) and `Track B` (SQLite Cache Schema) have zero cross-dependencies and can be executed concurrently.

### Track A: Provider Abstraction & AlienVault OTX Client

#### TASK-A01: Implement `ThreatIntelProvider` Protocol & `ThreatIntelResponse` Data Models
**Status:** ✅ Completed
**Dependencies:** None
**Requirements Satisfied:** FR-01, NFR-02

**Description:**
Define the abstract Python `typing.Protocol` for `ThreatIntelProvider` and the Pydantic v2 `ThreatIntelResponse` model under `src/blackwall/threat_intel/models.py`. Standardize indicators (`IPV4`, `IPV6`, `DOMAIN`, `URL`, `FILE_HASH`), risk scores ($0.0–1.0$), active pulse counts, threat tags, and malware families.

**Acceptance Criteria:**
1. Write a failing unit test asserting model validation, default field defaults, and JSON serialization.
2. `ThreatIntelResponse` parses benign and malicious payloads with normalized risk scores.
3. `ThreatIntelProvider` protocol type-checks cleanly with `mypy --strict`.
4. All unit tests pass.

#### TASK-A02: Implement `AlienVaultOTXProvider` with 10,000 Req/Hr Token Bucket
**Status:** ✅ Completed
**Dependencies:** TASK-A01
**Requirements Satisfied:** FR-02, NFR-01, US-01

**Description:**
Implement `AlienVaultOTXProvider` in `src/blackwall/threat_intel/otx.py` using `aiohttp`. Map endpoints for IPv4, IPv6, Domain, URL, and File Hashes. Enforce a token bucket of 10,000 tokens replenishing 1 token every 0.36 seconds (~166 RPM). Read credentials securely from `BW_OTX_API_KEY` or `~/.blackwall/config.yaml`.

**Acceptance Criteria:**
1. Write failing unit tests with mocked `aiohttp` responses for all 5 indicator types.
2. Verify token bucket permits burst queries without raising `429` or budget exhaustion errors.
3. Provider successfully queries IPv4, IPv6, domain, URL, and file hash endpoints with `X-OTX-API-KEY`.
4. Unauthenticated fallback operates with an informational warning and a 1,000 req/hr rate limit.
5. All unit tests pass.

#### TASK-A03: Implement OTX Pulse Parser & Threat Scoring Algorithm
**Status:** ✅ Completed
**Dependencies:** TASK-A02
**Requirements Satisfied:** FR-02, FR-06

**Description:**
Implement the pulse analysis algorithm in `AlienVaultOTXProvider`. Extract threat pulse names, tags, targeted industries, adversary attributions, and malware families. Compute normalized risk score:
$$\text{Risk} = \min\left(1.0, \frac{\text{pulse\_count} \times 0.25 + \text{malware\_pulse\_count} \times 0.50}{1.0}\right)$$
Set `is_malicious = True` when $\text{Risk} \ge 0.25$ or when linked to active malware pulses.

**Acceptance Criteria:**
1. Write unit tests with fixture OTX payloads representing benign, suspicious, and known-malware indicators.
2. Verified calculation of `risk_score` matches the mathematical specification.
3. Extraction of `malware_families` and `threat_categories` correctly parses complex OTX pulse lists.
4. All unit tests pass.

---

### Track B: SQLite Threat Intelligence Cache

#### TASK-B01: Create SQLite `threat_intel_cache` Schema & TTL Indices
**Status:** ✅ Completed
**Dependencies:** None
**Requirements Satisfied:** FR-05, NFR-01

**Description:**
Extend `SQLiteThreatRepository` in `src/blackwall/db/repository.py` to create the `threat_intel_cache` table and lookup indices in WAL mode. Support composite primary key `(indicator, indicator_type, provider)` and expiration timestamps.

**Acceptance Criteria:**
1. Write a failing migration test verifying schema creation and index presence.
2. Table and indices are created cleanly on existing and new SQLite database files.
3. Database executes in WAL mode with busy timeout configured.
4. All unit tests pass.

#### TASK-B02: Implement Cache Repository Operations with < 1ms SLA
**Status:** ✅ Completed
**Dependencies:** TASK-B01
**Requirements Satisfied:** FR-05, NFR-01

**Description:**
Implement `get_cached_threat_intel()`, `cache_threat_intel()`, and `prune_expired_threat_intel()` on `SQLiteThreatRepository`. Enforce 24-hour TTL for benign records and 6-hour TTL for malicious records. Benchmark cache hits to verify execution completes in $< 1.0\text{ ms}$.

**Acceptance Criteria:**
1. Write failing property-based and unit tests verifying write-read roundtrip, TTL expiration, and pruning.
2. Benchmark asserts 100 consecutive cache hits resolve with an average latency $\le 1.0\text{ ms}$.
3. Expired cache entries are filtered out during lookups and cleanly removed by `prune()`.
4. All unit tests pass.

---

## 🛤️ Phase 2: Supplementary Providers & Orchestration (Parallel Execution)

> [!TIP]
> **PARALLEL EXECUTION**
> `Track C` (AbuseIPDB and abuse.ch adapters) and `Track D` (Orchestrator and Circuit Breaker) can proceed concurrently once Phase 1 is complete.

### Track C: Supplementary Feed Adapters

#### TASK-C01: Implement `AbuseIPDBProvider` with Confidence Score Mapping
**Status:** ✅ Completed
**Dependencies:** TASK-A01
**Requirements Satisfied:** FR-03, NFR-03

**Description:**
Implement `AbuseIPDBProvider` in `src/blackwall/threat_intel/abuseipdb.py`. Query `https://api.abuseipdb.com/api/v2/check` using `Key: <API_KEY>` from `BW_ABUSEIPDB_API_KEY`. Restrict lookups to IP indicators and linearly map `abuseConfidenceScore` ($0–100$) to `risk_score` ($0.0–1.0$).

**Acceptance Criteria:**
1. Write failing unit tests with mocked AbuseIPDB responses.
2. Non-IP indicator lookups raise `ValueError` without triggering network requests.
3. Risk scores accurately map confidence percentages; scores $\ge 25$ set `is_malicious = True`.
4. All unit tests pass.

#### TASK-C02: Implement `AbuseChProvider` (ThreatFox, URLhaus, MalwareBazaar)
**Status:** ✅ Completed
**Dependencies:** TASK-A01
**Requirements Satisfied:** FR-04, NFR-02

**Description:**
Implement `AbuseChProvider` in `src/blackwall/threat_intel/abusech.py`. Integrate ThreatFox for multi-indicator queries with malware family attribution, URLhaus for malicious URLs, and MalwareBazaar for payload hashes.

**Acceptance Criteria:**
1. Write failing unit tests mocking ThreatFox, URLhaus, and MalwareBazaar endpoints.
2. Accurate extraction of malware family names (e.g. Cobalt Strike, QakBot).
3. Graceful handling of free-tier rate limits and missing Auth-Keys.
4. All unit tests pass.

---

### Track D: Threat Intelligence Orchestration & Resilience

#### TASK-D01: Implement `ThreatIntelOrchestrator` with Multi-Provider Cascade
**Status:** ✅ Completed
**Dependencies:** TASK-A02, TASK-B02
**Requirements Satisfied:** FR-01, NFR-01, NFR-04

**Description:**
Build `ThreatIntelOrchestrator` in `src/blackwall/threat_intel/orchestrator.py`. Orchestrate queries by:
1. Checking `threat_intel_cache` first (< 1ms).
2. Routing to primary provider (`AlienVaultOTXProvider`).
3. Cascading to secondary providers (`AbuseIPDBProvider`, `AbuseChProvider`) when configured.
4. Caching resolved results asynchronously.

**Acceptance Criteria:**
1. Write unit tests asserting cache-first short-circuiting.
2. When cache misses occur, primary provider is queried and result is stored in cache.
3. Multi-source score aggregation selects the highest confidence risk rating.
4. All unit tests pass.

#### TASK-D02: Implement Circuit Breaker & 3.0s Timeout Safeguards
**Status:** ✅ Completed
**Dependencies:** TASK-D01
**Requirements Satisfied:** NFR-01, NFR-04

**Description:**
Wrap all live provider calls with an asynchronous timeout ($3.0\text{s}$) and a 3-state circuit breaker (`CLOSED`, `OPEN`, `HALF-OPEN`). If a provider encounters 5 consecutive timeouts or connection errors, transition to `OPEN` for 60 seconds, gracefully degrading without raising unhandled exceptions to the caller.

**Acceptance Criteria:**
1. Write failing unit tests simulating network timeouts and consecutive connection drops.
2. Slow provider calls abort at 3.0 seconds, returning fallback heuristics.
3. 5 consecutive failures switch state to `OPEN`; requests during `OPEN` bypass the failing provider.
4. After 60 seconds, state transitions to `HALF-OPEN` and restores `CLOSED` upon 3 successful probes.
5. All unit tests pass.


---

## 🛤️ Phase 3: Native CLI & Harpoon Companion Bridge (Parallel Execution)

> [!TIP]
> **PARALLEL EXECUTION**
> `Track E` (CLI Tool Suite) and `Track F` (Harpoon OSINT Bridge) can be developed in parallel.

### Track E: Native `blackwall` CLI Suite

#### TASK-E01: Implement `blackwall check <indicator>` with Automatic Type Detection
**Status:** ⏳ Not Started
**Dependencies:** TASK-D01
**Requirements Satisfied:** FR-07, US-02

**Description:**
Implement `blackwall check <indicator>` in `src/blackwall/cli.py` using `click`. Build regex heuristics to auto-classify IPv4, IPv6, Domain, URL, MD5, SHA1, and SHA256 indicators. Render clean, formatted terminal tables showing verdict (`ALLOW`/`WARN`/`BLOCK`), risk score, active pulse count, and provider source. Add `--format json` flag.

**Acceptance Criteria:**
1. Write CLI runner tests using `click.testing.CliRunner` for each indicator format.
2. Auto-detection correctly classifies IP, domain, URL, and hash strings.
3. Command outputs formatted table in standard mode and valid JSON when `--format json` is passed.
4. Returns exit code `0` on successful lookup.
5. All unit tests pass.

#### TASK-E02: Implement `blackwall threat-intel` Subcommands
**Status:** ⏳ Not Started
**Dependencies:** TASK-E01
**Requirements Satisfied:** FR-07, US-02

**Description:**
Implement the `blackwall threat-intel` subcommand group:
- `blackwall threat-intel lookup <indicator> [--type] [--provider] [--no-cache]`
- `blackwall threat-intel pulse <pulse_id>`
- `blackwall threat-intel cache status|clear [--expired-only]`
- `blackwall threat-intel providers` (health & budget checks)

**Acceptance Criteria:**
1. Write CLI runner tests asserting all subcommands execute with expected flags.
2. `pulse` subcommand fetches and prints detailed pulse references and tags.
3. `cache status` reports total entries, size, and hit rates; `cache clear` evicts records deterministically.
4. `providers` displays connectivity and token bucket status without leaking API keys.
5. All unit tests pass.

---

### Track F: Harpoon OSINT Companion Bridge

#### TASK-F01: Implement `HarpoonBridge` Subprocess Runner & JSON Parser
**Status:** ⏳ Not Started
**Dependencies:** TASK-A01
**Requirements Satisfied:** FR-06, US-03

**Description:**
Build `HarpoonBridge` in `src/blackwall/threat_intel/harpoon.py`. Asynchronously invoke `harpoon otx <type> <indicator> --json` via `asyncio.create_subprocess_exec`, stream and parse JSON output, and map results into `ThreatIntelResponse`.

**Acceptance Criteria:**
1. Write unit tests with mocked subprocess stdout delivering valid and malformed JSON.
2. Correctly parses `harpoon` output into `ThreatIntelResponse` data structures.
3. Timeout enforced at 5.0 seconds for external subprocess execution.
4. All unit tests pass.

#### TASK-F02: Implement Harpoon Liveness Detection & Transparent Fallback
**Status:** ⏳ Not Started
**Dependencies:** TASK-F01
**Requirements Satisfied:** FR-06, US-03

**Description:**
Detect `harpoon` presence using `shutil.which("harpoon")`. If absent, log an informational notice and transparently delegate execution to `AlienVaultOTXProvider`.

**Acceptance Criteria:**
1. Write unit tests simulating absent `harpoon` binary on `PATH`.
2. System logs informational message and successfully returns data via built-in `AlienVaultOTXProvider`.
3. Zero unhandled exceptions or process aborts when `harpoon` is not installed.
4. All unit tests pass.

---

## 🛤️ Phase 4: SyncResolver Migration & BDD Integration (Sequential Execution)

### Track G: SyncResolver Migration & Breaking Changes

#### TASK-G01: Deprecate `GTIMCPClient` & `GTIQueryBudgetTracker`
**Status:** ⏳ Not Started
**Dependencies:** TASK-D01
**Requirements Satisfied:** FR-08

**Description:**
Safely deprecate and remove `src/blackwall/mcp/gti_client.py` and `src/blackwall/mcp/gti_budget_tracker.py`. Remove `GTIBudgetExhaustedError` and `GTIDegradedError` references from exception hierarchies.

**Acceptance Criteria:**
1. Stale GTI modules are removed from the codebase.
2. Grep search confirms zero remaining references to `GTIBudgetExhaustedError` across production source files.
3. Codebase compiles and imports cleanly.

#### TASK-G02: Integrate `ThreatIntelOrchestrator` into `SyncResolver`
**Status:** ⏳ Not Started
**Dependencies:** TASK-G01
**Requirements Satisfied:** FR-08, NFR-01, US-01

**Description:**
Refactor Step 5 of `SyncResolver` in `src/blackwall/sync_resolver.py`. Replace `_query_gti()` and `_score_gti()` with `_query_threat_intel()` using `ThreatIntelOrchestrator`. Expand rate-limiting ceiling from 4 RPM to 10,000 req/hr.

**Acceptance Criteria:**
1. Write failing unit tests for `SyncResolver` asserting threat intelligence evaluation with OTX responses.
2. Malicious indicators detected by OTX scale the overall composite score and trigger `BLOCK` verdicts.
3. Rate limiter comfortably handles sustained 150+ RPM bursts without query deferrals.
4. All unit tests pass.

#### TASK-G03: Migrate Existing Test Suites & Property Tests
**Status:** ⏳ Not Started
**Dependencies:** TASK-G02
**Requirements Satisfied:** FR-08

**Description:**
Update all unit, integration, and property-based tests in `tests/` that referenced GTI, updating fixtures to use `ThreatIntelResponse` and the new SQLite cache table.

**Acceptance Criteria:**
1. Run test suite: `pytest tests/unit tests/property`.
2. Zero failures across all migrated threat intelligence tests.
3. Overall test pass rate maintained at 100%.

---

### Track H: End-to-End BDD Scenarios & SLA Verification

#### TASK-H01: Implement Gherkin BDD Feature for High-Throughput Resolution
**Status:** ⏳ Not Started
**Dependencies:** TASK-G02
**Requirements Satisfied:** US-01, NFR-01

**Description:**
Implement Gherkin scenario in `tests/features/threat_intel_high_throughput.feature` and step definitions in `tests/step_defs/test_threat_intel_bdd.py`. Verify 20 consecutive network tool calls within 10 seconds complete without throttling.

**Acceptance Criteria:**
1. Execute `pytest tests/step_defs/test_threat_intel_bdd.py`.
2. All 20 calls process successfully; live queries complete within 2.0s; cache hits complete in $< 1\text{ ms}$.
3. BDD scenario passes.

#### TASK-H02: Implement Gherkin BDD Feature for Native CLI Triage
**Status:** ⏳ Not Started
**Dependencies:** TASK-E01
**Requirements Satisfied:** US-02

**Description:**
Implement Gherkin scenario verifying `blackwall check <indicator>` correctly triages benign, suspicious, and malicious domains, IPs, and hashes.

**Acceptance Criteria:**
1. Execute `pytest tests/step_defs/test_threat_intel_cli_bdd.py`.
2. BDD step definitions verify terminal table output and JSON formatting.
3. BDD scenario passes.

#### TASK-H03: Benchmarking & Memory Overhead Verification (< 50MB RSS)
**Status:** ⏳ Not Started
**Dependencies:** TASK-H01, TASK-H02
**Requirements Satisfied:** NFR-01, NFR-04

**Description:**
Execute benchmarking harness verifying:
1. Cache lookup latency is $\le 1.0\text{ ms}$ on 2019 MacBook Pro baseline.
2. RSS process memory overhead attributable to the threat intelligence engine remains $\le 50\text{ MB}$.
3. Zero CUDA/GPU allocations initiated.

**Acceptance Criteria:**
1. Benchmark script outputs latency statistics confirming $< 1.0\text{ ms}$ cache hits.
2. Memory profiling confirms RSS overhead $\le 50\text{ MB}$.
3. Conformance verified across macOS and Linux test environments.

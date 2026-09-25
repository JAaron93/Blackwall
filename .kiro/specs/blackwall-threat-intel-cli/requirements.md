# Requirements Document: Blackwall Threat Intelligence & Native CLI Engine

## Introduction

Blackwall is an autonomous **Agentic Security Firewall**. To ensure high-throughput execution without artificial rate-limiting bottlenecks, Blackwall 3.0 replaces the legacy Google Threat Intelligence (GTI) / VirusTotal dependency with a high-capacity, multi-provider **Threat Intelligence & Native CLI Engine**.

The system provides an in-process, async AlienVault OTX integration capable of processing **10,000 requests per hour (~166 RPM)** at **$0/month**, supplemented by optional low-cost feeds (AbuseIPDB, abuse.ch), a `harpoon` companion bridge, and a first-class native CLI suite (`blackwall check`, `blackwall threat-intel ...`).

This document defines the functional requirements, non-functional constraints, and behavior-driven acceptance criteria for the threat intelligence engine and CLI.

---

## Glossary

*   **OTX (Open Threat Exchange):** A crowd-sourced computer-security platform operated by LevelBlue (formerly AT&T Cybersecurity) providing community-generated threat indicators and pulses.
*   **Threat Pulse:** A curated collection of indicators of compromise (IOCs) associated with a specific threat actor, malware campaign, vulnerability, or attack technique.
*   **IOC (Indicator of Compromise):** Artifacts observed on a network or in an operating system that indicate a computer intrusion (e.g., IPv4/IPv6 addresses, domain names, URLs, MD5/SHA1/SHA256 file hashes).
*   **`ThreatIntelProvider`:** The internal Python protocol defining the lifecycle, lookup interface, and health reporting for all threat intelligence backends.
*   **`ThreatIntelResponse`:** The normalized Pydantic v2 data model returned by all providers, standardizing risk scores ($0.0–1.0$), active pulse counts, threat tags, and malware families.
*   **`HarpoonBridge`:** The internal Blackwall subsystem that discovers and communicates with the external `harpoon` CLI binary for deep interactive investigations and OSINT pivoting.
*   **`threat_intel_cache`:** The SQLite table in Blackwall's embedded database storing threat reputation records with time-to-live (TTL) expiration.
*   **Token Bucket:** A rate-limiting algorithm enforcing maximum request throughput while permitting burst capacity without triggering HTTP 429 errors.

---

## Functional Requirements

### FR-01: Pluggable `ThreatIntelProvider` Interface
Blackwall MUST define an abstract Python protocol (`ThreatIntelProvider`) standardizing indicator lookups across external threat intelligence platforms.
1. All providers MUST expose:
   - `name: str` — Provider identifier (e.g., `otx`, `abuseipdb`, `abusech`, `virustotal`).
   - `supported_indicators: set[IndicatorType]` — Supported indicator categories (`IPV4`, `IPV6`, `DOMAIN`, `URL`, `FILE_HASH`).
   - `async def lookup(indicator: str, indicator_type: IndicatorType, timeout: float = 3.0) -> ThreatIntelResponse`
   - `async def is_healthy() -> bool`
   - `def get_remaining_budget() -> int`
2. All provider outputs MUST be normalized into the standard `ThreatIntelResponse` model.

### FR-02: Native In-Process AlienVault OTX Provider
Blackwall MUST implement a pure-Python, asynchronous AlienVault OTX client (`AlienVaultOTXProvider`) using `aiohttp`.
1. **Authentication:** The provider MUST read the API key from `BW_OTX_API_KEY` or `~/.blackwall/config.yaml`. If no key is set, the provider MUST log a warning and run in degraded mode (unauthenticated rate limit of 1,000 req/hr).
2. **Indicator Coverage:**
   - IPv4 / IPv6: Queries `/api/v1/indicators/IPv4/{ip}/general` and `/api/v1/indicators/IPv6/{ip}/general`.
   - Domain / Hostname: Queries `/api/v1/indicators/domain/{domain}/general`.
   - URL: Queries `/api/v1/indicators/url/{url}/general`.
   - File Hash (MD5, SHA1, SHA256): Queries `/api/v1/indicators/file/{hash}/general`.
3. **Throughput Management:** The provider MUST maintain a token bucket with a capacity of 10,000 tokens and a replenishment interval of 0.36 seconds (~166 RPM). Queries MUST NOT block or fail if tokens are available.
4. **Risk Scoring:** The provider MUST calculate a normalized `risk_score` ($0.0–1.0$) based on pulse counts, malware-tagged pulses, and adversary attribution. An indicator with $\ge 1$ malware-associated pulse MUST be flagged as `is_malicious = True`.

### FR-03: AbuseIPDB Provider Support (Optional Low-Cost Tier)
Blackwall MUST implement an optional `AbuseIPDBProvider` for dedicated IP address reputation.
1. **Activation:** Enabled automatically when `BW_ABUSEIPDB_API_KEY` is present.
2. **Endpoint:** Queries `https://api.abuseipdb.com/api/v2/check` with header `Key: <API_KEY>`.
3. **Indicator Scope:** Restricted strictly to `IndicatorType.IPV4` and `IndicatorType.IPV6`. Non-IP queries MUST raise a `ValueError` without sending network requests.
4. **Score Mapping:** Linearly maps `data.abuseConfidenceScore` ($0–100$) to `risk_score` ($0.0–1.0$). If `abuseConfidenceScore >= 25`, the indicator MUST be flagged as `is_malicious = True`.

### FR-04: abuse.ch Multi-Feed Provider Support
Blackwall MUST implement a community-tier `AbuseChProvider` integrating abuse.ch feeds:
1. **ThreatFox:** Queries `https://threatfox-api.abuse.ch/api/v1/` for IOC search with malware family tags and confidence ratings ($0–100$).
2. **URLhaus:** Queries `https://urlhaus-api.abuse.ch/v1/url/` for active payload download URLs.
3. **MalwareBazaar:** Queries `https://mb-api.abuse.ch/api/v1/` for MD5 and SHA256 file hashes.
4. **Pricing:** 100% Free; optional `BW_ABUSECH_AUTH_KEY` header for authenticated fair use.

### FR-05: Local SQLite Threat Intelligence Cache
Blackwall MUST maintain persistent caching in SQLite (`threat_intel_cache` table in WAL mode):
1. **Cache Key:** Composite primary key on `(indicator, indicator_type, provider)`.
2. **Time-To-Live (TTL):**
   - Benign indicators (`is_malicious = False`): Default TTL of 24 hours (86,400 seconds).
   - Malicious indicators (`is_malicious = True`): Default TTL of 6 hours (21,600 seconds) to allow rapid threat remediation and avoid persistent false positives.
3. **SLA:** Cache hits MUST resolve in $< 1\text{ ms}$ without spawning background threads or making external network connections.
4. **Cache Eviction:** Automatic purging of expired entries on database initialization and manual purging via CLI (`blackwall threat-intel cache clear`).

### FR-06: Harpoon Companion Bridge
Blackwall MUST implement an interactive bridge to the `harpoon` OSINT CLI:
1. **Binary Detection:** Detects `harpoon` on `PATH` via `shutil.which("harpoon")`.
2. **Command Invocation:** Executes `harpoon otx <type> <indicator> --json` in an asynchronous subprocess with a 5.0s timeout.
3. **Graceful Fallback:** If `harpoon` is not installed or the subprocess fails, the system MUST log an informational message and transparently fall back to the built-in `AlienVaultOTXProvider`.

### FR-07: Native `blackwall` CLI Tool Suite
Blackwall MUST implement a first-class CLI in `src/blackwall/cli.py`:
1. **`blackwall check <indicator>`:**
   - Automatically detects indicator type (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256).
   - Outputs a clean terminal table summarizing verdict (`ALLOW`, `WARN`, `BLOCK`), risk score, active threat pulses, and provider source.
   - Supports `--format table|json` and `--no-cache`.
2. **`blackwall threat-intel lookup <indicator>`:**
   - Explicit indicator inspection with `--type`, `--provider`, and `--verbose` options.
3. **`blackwall threat-intel pulse <pulse_id>`:**
   - Fetches detailed pulse metadata, threat actor tags, and external references from AlienVault OTX.
4. **`blackwall threat-intel cache status|clear`:**
   - Inspects cache volume and hit rates; purges expired or all cached entries.
5. **`blackwall threat-intel providers`:**
   - Validates configured provider credentials, network liveness, and remaining token bucket allowances.

### FR-08: `SyncResolver` Migration & Breaking Changes (3.0.0)
Blackwall 3.0 MUST update the synchronous firewall resolution pipeline:
1. **Deprecate GTI Client:** Completely remove `GTIMCPClient` and `GTIQueryBudgetTracker`.
2. **Integrate `ThreatIntelOrchestrator`:** Step 5 of `SyncResolver` evaluates indicators via `ThreatIntelOrchestrator.lookup()`.
3. **Throughput Contract:** The firewall MUST support sustained workloads of at least 150 requests per minute without dropping or deferring queries due to external threat intelligence rate limits.
4. **Backward Compatibility Mode:** ~~If `BW_THREAT_INTEL_BACKEND=virustotal` is explicitly configured, Blackwall routes requests to the legacy `VirusTotalProvider`.~~ **Corrected during the PR #170 agent-instruction audit:** never implemented. No `VirusTotalProvider` exists in `src/blackwall/threat_intel/` and no code reads `BW_THREAT_INTEL_BACKEND`. The configured alternative primary provider is `HarpoonBridge` wrapping OTX, selected via `BW_THREAT_INTEL_PRIMARY=harpoon|harpoon-otx`.

---

## Non-Functional Requirements

### NFR-01: Latency & Performance SLA
* **Cached Lookups:** Must resolve in $\le 1.0\text{ ms}$.
* **Live Network Lookups:** Must complete within an upper bound of $2,000\text{ ms}$.
* **Hard Timeout:** Network calls must be terminated with a strict timeout of $3.0\text{ seconds}$, falling back to local threat graph heuristics so agent tool execution is never indefinitely hung.

### NFR-02: Zero Stale External MCP Daemons
The threat intelligence engine MUST be entirely self-contained within Python (`aiohttp` / `asyncio`). It MUST NOT require running Node.js binaries, NPM packages, or external unmaintained MCP servers.

### NFR-03: Token & Credential Hygiene
API keys (`BW_OTX_API_KEY`, `BW_ABUSEIPDB_API_KEY`) MUST NOT be written to plaintext logs, committed to source control, or exposed in JSON-RPC error responses returned to intercepted agents.

### NFR-04: Process Memory Footprint
The RSS memory footprint of the threat intelligence engine must remain $\le 50\text{ MB}$, ensuring compatibility with 2019 MacBook Pro hardware baselines and NVIDIA DGX Spark co-existence rules.

### NFR-05: Cross-Platform Compatibility
The CLI and threat intelligence engine must function identically across macOS (Apple Silicon `arm64` and Intel `x86_64`) and GNU/Linux (Ubuntu 22.04/24.04 and DGX OS `aarch64`).

---

## Behavior-Driven Development (BDD) Scenarios

### Scenario 1: High-Frequency Tool Calls Processed Without Throttling
```gherkin
Feature: High-Throughput Threat Intelligence Resolution
  As an AI agent executing multi-tool workflows
  I want external network indicators validated without artificial 4 RPM rate limits
  So that my task execution is not blocked or failed by budget exhaustion

  Scenario: Agent performs 20 consecutive network tool calls within 10 seconds
    Given the AlienVault OTX provider is configured with a valid API key
    And the legacy GTI token bucket is disabled
    When the agent invokes tools targeting 20 distinct external IP addresses
    Then all 20 indicator checks must be processed without GTIBudgetExhaustedError
    And each live query must complete within 2.0 seconds
    And subsequent identical tool calls must return from cache in under 1ms
```

### Scenario 2: Direct CLI Indicator Triage
```gherkin
Feature: Native CLI Threat Intelligence Triage
  As a developer or security engineer
  I want to inspect an indicator directly from the terminal
  So that I can verify Blackwall's threat intelligence without writing custom scripts

  Scenario: Checking a malicious domain via CLI
    Given a known malicious C2 domain "malicious-c2.xyz" exists in OTX with 3 active pulses
    When the developer executes "blackwall check malicious-c2.xyz"
    Then the CLI must output a table displaying verdict "BLOCK"
    And the risk score must be greater than or equal to 0.50
    And the threat provider must indicate "otx"
    And the command exit code must be 0
```

### Scenario 3: Harpoon Bridge Graceful Fallback
```gherkin
Feature: Harpoon Companion Bridge Resilience
  As a Blackwall deployment
  I want deep OSINT enrichment through harpoon when present, with automatic fallback when absent
  So that missing external CLI dependencies do not crash the firewall

  Scenario: Harpoon binary is not installed on the host
    Given the "harpoon" executable is absent from the host PATH
    When a threat intelligence lookup is triggered with deep enrichment requested
    Then Blackwall must log an informational notice about harpoon unavailability
    And Blackwall must fall back to the in-process AlienVaultOTXProvider
    And the lookup must succeed with standard pulse data
```

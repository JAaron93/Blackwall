# ADR 0005: Migration to AlienVault OTX & Native CLI Threat Intelligence Engine

## Status
Approved (Supersedes ADR 0002)

## Context
In Blackwall 2.0 (ADR 0002), we introduced Google Threat Intelligence (GTI) / VirusTotal as a secondary validation layer. While ADR 0002 successfully mitigated the 4 RPM free-tier constraint for low-frequency events by reserving GTI for high-risk alerts only, real-world deployment in multi-agent environments revealed fundamental scaling bottlenecks:
1. **Severe 4 RPM Hard Cap:** Under high-frequency tool calling (agents executing 10–20 tool calls in bursts), the 4 RPM token bucket (1 token every 15s) exhausts almost immediately, triggering query deferrals and false-alarm budget exhaustion penalties.
2. **Prohibitive Paid Tier Floor:** Upgrading VirusTotal beyond 4 RPM requires an enterprise contract exceeding $1,000/month (~$10,000–$20,000/year), rendering Blackwall unusable for individual developers and small open-source teams.
3. **Stale Community MCP Daemons:** Existing third-party MCP servers for alternative threat feeds (e.g., `mrwadams/otx-mcp`, `fastmcp-threatintel`) have been abandoned for over a year, introducing unmaintained dependencies, Node.js runtime bloat, and fragile external stdio subprocess management.

Blackwall requires a high-throughput, zero-cost, fully supported threat intelligence architecture that maintains full indicator parity while preserving the resilience guarantees established in 2.0.

## Decision
We supersede ADR 0002 and replace the GTI/VirusTotal MCP client with an **in-process AlienVault OTX Threat Intelligence & Native CLI Engine**, integrated with a `harpoon otx` companion bridge and native `blackwall` CLI subcommands.

### 1. Drop-In Indicator Parity & Throughput (10,000 Req/Hour)
AlienVault OTX acts as a complete drop-in replacement across all four core indicator categories:
- **IPv4 & IPv6:** ASN, passive DNS, geo-reputation, and associated threat pulses.
- **Domains & Hostnames:** Passive DNS, WHOIS records, subdomains, and malicious status.
- **URLs:** Targeted host classification, HTTP responses, and active campaign links.
- **File Hashes (MD5, SHA1, SHA256):** Multi-antivirus detections, malware families, and static metadata.

**Throughput & Cost:**
- **Capacity:** 10,000 requests per hour (~166 RPM) with a standard free registered API key (vs. VirusTotal's 4 RPM) — a **41.5× throughput improvement**.
- **Cost:** $0/month (100% community free).
- **Unauthenticated Fallback:** 1,000 requests per hour for out-of-the-box evaluation without an API key.

### 2. How the 2.0 Resilience Primitives Complement AlienVault OTX
The resilience infrastructure built in ADR 0002 is directly reused and upgraded:

* **Token Bucket Architecture:**
  The `GTIQueryBudgetTracker` is refactored into a generic `TokenBucketLimiter` for OTX:
  - Capacity: 10,000 tokens (upgraded from 4).
  - Replenishment: 1 token every 0.36 seconds (upgraded from 15.0s).
  - Guarantees burst resilience while preventing accidental 429 backpressure.

* **Cache-First Short Circuiting (`< 1ms`):**
  The SQLite cache is upgraded from `gti_cache` to `threat_intel_cache` (WAL mode):
  - Benign indicators: Cached for 24 hours.
  - Malicious indicators: Cached for 6 hours (allowing timely threat remediation).
  - Cache hits return in $< 1.0\text{ ms}$, sparing external network calls for repeated indicators.

* **3-State Circuit Breaker (`CLOSED` ➔ `OPEN` ➔ `HALF-OPEN`):**
  If AlienVault OTX experiences network timeouts or upstream downtime (5 consecutive connection failures):
  - Transitions to `OPEN` (degraded mode) for a 60-second cooldown.
  - Transparently steps down to secondary feeds (abuse.ch / AbuseIPDB) or local heuristics.
  - Probes recovery in `HALF-OPEN` before restoring normal operation.

* **Fail-Safe Local Heuristics:**
  If external network access is blocked or all threat providers are offline, Blackwall never fails open blindly. It falls back to:
  - Local SQLite Threat Signature Graph (FTS5 word-level intersection).
  - Codebase Memory AST dependency query.
  - Structural YAML firewall policies.

### 3. Native CLI & Harpoon Companion Bridge
- **In-Process Engine:** Runs natively inside Blackwall via `aiohttp` (zero external Node.js/MCP sub-daemons).
- **`harpoon otx` Companion Bridge:** For interactive terminal investigations and OSINT pivoting, Blackwall interfaces with `harpoon` (`pip install harpoon`) when installed.
- **Unified Native CLI:** Exposes `blackwall check <indicator>` (auto-type detection) and `blackwall threat-intel ...` directly in developer terminals.

## Consequences

### Positive
- Eliminates the 4 RPM token exhaustion false-positive blockers in `SyncResolver`.
- Zero monthly subscription barrier for developers ($0/mo vs $1,000+/mo).
- Complete indicator coverage (IP, domain, URL, hash) with threat pulse attribution.
- Zero external daemon process management or Node.js runtime baggage.

### Negative / Breaking Changes (3.0.0)
- Deprecates and removes `GTIMCPClient` and `GTIQueryBudgetTracker`.
- Removes `GTIBudgetExhaustedError` and `GTIDegradedError` exceptions.
- Requires migrating `gti_cache` SQLite table schema to `threat_intel_cache`.
- ~~Legacy VirusTotal access is retained strictly as an opt-in fallback via `BW_THREAT_INTEL_BACKEND=virustotal`.~~ **Corrected during the PR #170 agent-instruction audit:** this fallback was never implemented. No VirusTotal client exists in `src/blackwall/threat_intel/` and `BW_THREAT_INTEL_BACKEND` is read by no code path. The configured alternative primary provider is `HarpoonBridge` wrapping OTX, selected via `BW_THREAT_INTEL_PRIMARY=harpoon|harpoon-otx`.

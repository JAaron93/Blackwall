# Design Document: Blackwall Threat Intelligence & Native CLI Engine

## Overview

Blackwall is an autonomous **Agentic Security Firewall** designed to intercept execution flows at machine speed before rogue or compromised AI agents can execute unauthorized operating system commands, chain zero-day exploits, exfiltrate credentials, or connect to malicious external infrastructure.

In Blackwall 2.0.0-MVP, secondary validation of external indicators (IP addresses, domain names, URLs, and file hashes) relied exclusively on a Google Threat Intelligence (GTI) MCP client wrapping the VirusTotal v3 REST API. This created two critical blockers for real-world adoption:
1. **Severe Free-Tier Throttling:** VirusTotal's public API restricts callers to **4 requests per minute** (and 500 requests per day). This forced Blackwall to install a strict token bucket (`GTIQueryBudgetTracker`) releasing 1 token every 15 seconds, creating false-positive `GTIBudgetExhaustedError` exceptions during high-frequency agent tool calling.
2. **Prohibitive Paid-Tier Floor:** Upgrading VirusTotal beyond 4 RPM requires an enterprise contract exceeding **$1,000/month** (~$10,000–$20,000/year), which is completely unfeasible for individual developers and small agent teams.
3. **Stale Community MCP Implementations:** Available open-source MCP servers for alternative feeds (such as `mrwadams/otx-mcp` or `fastmcp-threatintel`) have been abandoned for over a year, introducing fragile stdio subprocess lifecycles, Node.js dependencies, and unmaintained supply chains.

Blackwall 3.0 resolves these limitations by introducing the **Blackwall Threat Intelligence & Native CLI Engine**. This system:
- Implements an **in-process, async AlienVault OTX provider** delivering **10,000 requests per hour (~166 RPM)** at **$0/month** with full indicator parity (IPv4/IPv6, domains, URLs, and MD5/SHA1/SHA256 hashes).
- Provides an extensible **`ThreatIntelProvider` abstraction** supporting optional low-cost feeds (AbuseIPDB Basic at $19/month for 10,000 checks/day, abuse.ch ThreatFox/URLhaus/MalwareBazaar, and legacy VirusTotal opt-in).
- Integrates a **`harpoon` companion bridge** for deep interactive OSINT investigations and threat pivoting.
- Exposes a unified **`blackwall` Native CLI tool suite** (`blackwall check`, `blackwall threat-intel lookup/pulses/cache`) that works seamlessly both standalone in developer terminals and in tandem with the Blackwall MCP Gateway daemon.

---

## Core Architectural Principle

Blackwall's threat intelligence architecture transitions from an external, rate-throttled MCP dependency to an **in-process, multi-provider threat engine** managed directly within Blackwall Core.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Developer Terminal                                   │
│                                                                                        │
│   ┌───────────────────────────────┐              ┌─────────────────────────────────┐   │
│   │ blackwall check <indicator>   │              │ harpoon otx <indicator>         │   │
│   │ blackwall threat-intel ...    │              │ (Deep Interactive Forensics)    │   │
│   └───────────────┬───────────────┘              └────────────────┬────────────────┘   │
└───────────────────┼───────────────────────────────────────────────┼────────────────────┘
                    │                                               │
                    ▼                                               ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              Blackwall Engine / Gateway Daemon                         │
│                                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │                         SyncResolver Interception Flow                         │   │
│   │  Rate Check → Sanitization → Threat Graph → CBM AST → Threat Intel → Verdict   │   │
│   └───────────────────────────────────────┬────────────────────────────────────────┘   │
│                                           │                                            │
│                                           ▼                                            │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │                         ThreatIntelOrchestrator                                │   │
│   │                                                                                │   │
│   │   ┌────────────────────────┐                    ┌──────────────────────────┐   │   │
│   │   │ Local SQLite Cache     │◄── Cache Hit ─────►│ Match & Scoring Engine   │   │   │
│   │   │ (threat_intel_cache)   │    (< 1ms)         │ (Normalized Risk 0.0-1.0)│   │   │
│   │   └────────────────────────┘                    └──────────────────────────┘   │   │
│   │                                                                                │   │
│   │   ┌────────────────────────────────────────────────────────────────────────┐   │   │
│   │   │                     Pluggable Provider Adapters                        │   │   │
│   │   │                                                                        │   │   │
│   │   │  ┌───────────────────────┐  ┌───────────────────┐  ┌────────────────┐  │   │   │
│   │   │  │ AlienVault OTX        │  │ AbuseIPDB         │  │ abuse.ch       │  │   │   │
│   │   │  │ (Primary / Free)      │  │ (Optional: $19/mo)│  │ (ThreatFox,    │  │   │   │
│   │   │  │ • 10,000 req/hr       │  │ • 10,000 req/day  │  │  MalwareBazaar,│  │   │   │
│   │   │  │ • IP/Dom/URL/Hash     │  │ • IP Confidence % │  │  URLhaus)      │  │   │   │
│   │   │  └───────────────────────┘  └───────────────────┘  └────────────────┘  │   │   │
│   │   │                                                                        │   │   │
│   │   │  ┌───────────────────────┐  ┌───────────────────┐                      │   │   │
│   │   │  │ Harpoon CLI Bridge    │  │ VirusTotal / GTI  │                      │   │   │
│   │   │  │ (Subprocess / JSON)   │  │ (Legacy Opt-In)   │                      │   │   │
│   │   │  └───────────────────────┘  └───────────────────┘                      │   │   │
│   │   └────────────────────────────────────────────────────────────────────────┘   │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. The `ThreatIntelProvider` Protocol
All threat intelligence backends implement a standard, non-blocking Python `typing.Protocol`:

```python
class ThreatIntelProvider(Protocol):
    name: str
    supported_indicators: set[IndicatorType]

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType, timeout: float = 3.0
    ) -> ThreatIntelResponse: ...

    async def is_healthy(self) -> bool: ...

    def get_remaining_budget(self) -> int: ...
```

#### Normalized Response Model (`ThreatIntelResponse`)
Blackwall normalizes all provider outputs into a vendor-agnostic Pydantic v2 data model:
```python
class ThreatIntelResponse(BaseModel):
    indicator: str
    indicator_type: IndicatorType
    is_malicious: bool
    risk_score: float  # Normalized 0.0 (benign) to 1.0 (critical threat)
    detection_count: int = 0
    total_engines: int = 0
    threat_categories: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    pulse_count: int = 0
    references: list[str] = Field(default_factory=list)
    provider_name: str
    cached: bool = False
    raw_response: dict[str, Any] = Field(default_factory=dict, exclude=True)
```

---

### 2. Primary Provider: `AlienVaultOTXProvider`
* **Direct Async REST Client:** Connects via `aiohttp` to `https://otx.alienvault.com/api/v1/`.
* **Authentication:** Uses the `X-OTX-API-KEY` HTTP request header populated from `BW_OTX_API_KEY` or `~/.blackwall/config.yaml`.
* **Endpoints Mapped:**
  - IPv4 / IPv6: `/api/v1/indicators/IPv4/{ip}/general` & `/api/v1/indicators/IPv6/{ip}/general`
  - Domains / Hostnames: `/api/v1/indicators/domain/{domain}/general`
  - URLs: `/api/v1/indicators/url/{url}/general`
  - File Hashes (MD5, SHA1, SHA256): `/api/v1/indicators/file/{hash}/general`
* **Throughput Capacity:** 10,000 queries per hour (~166 RPM). The provider uses a token bucket replenishing tokens smoothly (1 token every 0.36 seconds), preventing burst throttling while avoiding 429 backpressure.
* **Risk Scoring Algorithm:**
  $$\text{Risk} = \min\left(1.0, \frac{\text{pulse\_count} \times 0.25 + \text{malware\_pulse\_count} \times 0.50}{1.0}\right)$$
  Flagged as `is_malicious = True` whenever $\text{Risk} \ge 0.25$ or when linked to an active threat pulse containing known malware tags or threat actor attributions.

---

### 3. Secondary & Optional Providers

#### A. `AbuseIPDBProvider` (Optional Low-Cost Network Engine)
* **Target:** IP indicators only.
* **Configuration:** Enabled when `BW_ABUSEIPDB_API_KEY` is provided.
* **Pricing Integration:** Uses AbuseIPDB's $19/month Basic plan (10,000 checks/day) or free tier (1,000 checks/day).
* **Endpoint:** `GET https://api.abuseipdb.com/api/v2/check` with header `Key: <API_KEY>`.
* **Risk Mapping:** Maps `abuseConfidenceScore` (0–100) linearly to `risk_score` ($0.0–1.0$).

#### B. `AbuseChProvider` (Free Community Feeds)
* **Target:** ThreatFox (IOCs + Malware families), URLhaus (Malicious URLs), MalwareBazaar (File hashes).
* **Pricing:** 100% Free community fair-use API with `Auth-Key`.
* **Zero Cost Parity:** Provides high-fidelity malware family correlation (e.g., QakBot, Cobalt Strike, Lumma Stealer) without commercial subscriptions.

#### C. `VirusTotalProvider` (Legacy Opt-in) — NOT IMPLEMENTED
* ~~Retained under `BW_THREAT_INTEL_BACKEND=virustotal` for enterprise organizations with existing commercial VirusTotal subscriptions.~~
* ~~Constrained to 4 RPM if an unauthenticated or public API key is detected.~~
* **Corrected during the PR #170 agent-instruction audit:** this provider was never built. No `VirusTotalProvider` exists in `src/blackwall/threat_intel/` and `BW_THREAT_INTEL_BACKEND` is read by no code path; `GTIResponse` survives only as a response schema. The alternative primary provider that does exist is `HarpoonBridge`, selected via `BW_THREAT_INTEL_PRIMARY=harpoon|harpoon-otx`.

---

### 4. Harpoon Companion Bridge (`HarpoonBridge`)
* **Purpose:** Allows security engineers to invoke `harpoon` directly from Blackwall for interactive investigations and automated deep enrichment.
* **Execution Model:**
  - Inspects host system for `harpoon` executable (`shutil.which("harpoon")`).
  - Executes isolated subprocesses: `harpoon otx <type> <indicator> --json`.
  - Captures structured JSON streams and parses pulse associations, related infrastructure, and passive DNS records.
  - Safe error handling: If `harpoon` is not installed, Blackwall transparently falls back to its built-in in-process `AlienVaultOTXProvider` without raising exceptions.

---

### 5. Local SQLite Threat Intelligence Cache (`threat_intel_cache`)
To guarantee sub-millisecond resolver responses for known indicators, Blackwall maintains a persistent cache table in its embedded SQLite database:

```sql
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    is_malicious INTEGER NOT NULL,
    risk_score REAL NOT NULL,
    payload JSON NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (indicator, indicator_type, provider)
);

CREATE INDEX IF NOT EXISTS idx_threat_cache_lookup 
ON threat_intel_cache(indicator, indicator_type, expires_at);
```

* **Default TTL:** 24 hours (86,400 seconds) for benign indicators; 6 hours (21,600 seconds) for malicious indicators to ensure timely revocation.
* **Fast-Path Interception:** `SyncResolver` checks `threat_intel_cache` *before* initiating network requests. If a non-expired entry exists, it returns in `< 1ms` with `cached = True`.

---

### 6. Native `blackwall` CLI Tool Suite

Blackwall provides a developer-friendly command line interface implemented in `src/blackwall/cli.py` using `click`:

#### Subcommand: `blackwall check <indicator>`
Direct, single-argument CLI inspection of any indicator with automatic type detection:
```bash
# Automatically detects IPv4
blackwall check 198.51.100.1

# Automatically detects domain
blackwall check malicious-c2.xyz --format json

# Automatically detects SHA256 hash
blackwall check 44d88612fea8a8f36de82e1278abb02f --provider otx
```

#### Subcommand Suite: `blackwall threat-intel`
Comprehensive threat intelligence management:
* `blackwall threat-intel lookup <indicator> [--type ip|domain|url|hash] [--provider otx|abuseipdb|all] [--no-cache]`
* `blackwall threat-intel pulse <pulse_id>` — Fetch full OTX pulse details, tags, and references.
* `blackwall threat-intel cache status` — Print cache hit count, size, and expired entries.
* `blackwall threat-intel cache clear [--expired-only]` — Purge cached threat intel entries.
* `blackwall threat-intel providers` — Test connectivity, API keys, and remaining rate-limit quotas across configured providers.

---

### 7. `SyncResolver` Integration & Breaking Changes (3.0.0)

Blackwall 3.0 breaks backward compatibility with the legacy GTI/VirusTotal pipeline:
1. **Deprecation of GTI Modules:**
   - Remove `src/blackwall/mcp/gti_client.py` and `src/blackwall/mcp/gti_budget_tracker.py`.
   - Remove `GTIBudgetExhaustedError` and `GTIDegradedError`.
2. **Introduction of Threat Intelligence Engine:**
   - Introduce `src/blackwall/threat_intel/` module containing `orchestrator.py`, `otx.py`, `abuseipdb.py`, `abusech.py`, `models.py`, and `cache.py`.
3. **Resolution Sequence Update:**
   - Step 5 in `SyncResolver`: Replaces `_query_gti()` with `_query_threat_intel()`.
   - The rate limit ceiling expands from 4 RPM to 10,000 req/hr. Threat intel checks are no longer deferred due to trivial budget exhaustion.

---

## Architectural Constraints & Invariants

1. **Pure Python & Zero Stale Daemon Subprocesses:** The threat intelligence engine runs in-process using `asyncio` and `aiohttp`. No external Node.js servers, FastMCP daemon processes, or unmaintained Python sub-daemons are permitted.
2. **Non-Blocking I/O SLA:** All external API requests must execute with a hard timeout of `3.0s`. If a provider times out, the orchestrator gracefully degrades to cached data or local threat signature graph heuristics without blocking agent tool execution.
3. **Token & Credential Hygiene:** API keys (`BW_OTX_API_KEY`, `BW_ABUSEIPDB_API_KEY`) must never be logged, printed to standard error, or exposed in JSON-RPC error payloads returned to intercepted agents.
4. **Hardware Footprint:** RSS memory overhead of the threat intelligence engine must remain $\le 50\text{ MB}$, preserving compatibility with 2019 MacBook Pro baselines and NVIDIA DGX Spark co-existence boundaries.

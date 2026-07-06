# ADR 0002: GTI MCP as Secondary Validation Layer with Intelligent Rate-Limit Budgeting

## Status
Approved

## Context
During Task 18 implementation, we discovered that the Google Threat Intelligence (GTI) MCP integration uses the VirusTotal API, which has strict rate limits on the free tier:
- **Free tier**: 4 lookups per minute (hard cap)
- **Premium tier**: Starts at $1,600/month (completely untenable for hackathon project)

Our original architecture envisioned GTI as a **"Live Referee"** that would be queried for every intercepted event requiring external threat intelligence validation. With Blackwall operating at up to 300 RPM (Gemini paid tier) and defending against attackers running at 600 RPM, the 4 lookups/minute GTI constraint creates a critical bottleneck.

Furthermore, querying GTI for every event would:
1. Exhaust the budget within 15 seconds at 300 RPM interception rate
2. Force 99%+ of evaluations to proceed without GTI validation
3. Create false dependency on external API for core blocking decisions
4. Introduce unpredictable latency spikes when budget exhausted

The original threat score formula (GTI 40% + CBM 30% + Context 30%) assumed GTI would be available for most high-risk events, but this assumption is invalidated by the rate limit.

## Decision
We redesigned the GTI MCP integration from a **primary threat intelligence source** to a **rate-limited secondary validation layer for high-risk events only**, with the following architectural changes:

### 1. Primary Defense (No GTI Required)
The core blocking decisions now rely exclusively on:
- **SQLiteThreatRepository**: Self-learning threat signature graph with cosine similarity matching (<10ms local queries)
- **Structural YAML Policies**: Fast deterministic rules (<5ms evaluation)
- **Codebase_Memory_MCP**: AST-based critical sink detection and dependency chain analysis

These components provide the **primary defense** and can operate indefinitely without external API calls.

### 2. GTI Query Budget Tracker (Token Bucket)
We introduced a new `GTI_Query_Budget_Tracker` component implementing a token bucket rate limiter:
- **Capacity**: 4 tokens (matching VirusTotal free tier)
- **Replenishment**: 1 token every 15 seconds (4 tokens per 60-second sliding window)
- **Hard cap**: Maximum 4 tokens (no accumulation beyond capacity)
- **Thread-safe**: Uses `asyncio.Lock` for concurrent access

The budget tracker exposes:
- `tryAcquire() -> bool`: Attempts to consume 1 token; returns `false` if budget exhausted
- `getAvailableTokens() -> int`: Returns current token count (0-4)
- `getMetrics() -> BudgetMetrics`: Tracks queries attempted, executed, deferred, cache hit rate

### 3. High-Risk Event Classification
GTI queries are now **reserved exclusively** for high-risk events classified by:
- **IOC Novelty**: New external IP addresses, domains, or file hashes not in local cache
- **Structural Signals**: YAML policy rules flagging elevated threat indicators
- **Domain Reputation**: Unknown domains with suspicious TLDs or DNS patterns
- **Geolocation Risk**: IPs from high-risk geographic regions
- **Entropy Analysis**: File hashes with high randomness suggesting obfuscation

Events are assigned a **suspicion score** (0.0-1.0) combining these signals. Only the top-N highest-scoring events within budget constraints trigger GTI queries.

### 4. Graceful Degradation
When GTI budget is exhausted (`tryAcquire()` returns `false`):
- **Continue evaluation** using Threat_Signature_Graph and Codebase_Memory_MCP signals only
- **Apply 0.2 threat score penalty** for missing GTI validation (reduced from original 0.3)
- **Redistribute GTI weight** (40%) proportionally: CBM gains +20%, Context gains +20%
- **Defer low-priority queries** until budget replenishes
- **No circuit breaker trigger**: Budget exhaustion is distinct from service failure

This ensures Blackwall remains **fully operational** even when GTI budget is completely consumed.

### 5. Updated Requirements
- **Requirement 9**: Complete redesign positioning GTI as secondary validator with token bucket
- **Requirement 5.7-5.9**: Added high-risk classification, suspicion scoring, budget checking
- **Requirement 5.12**: Weight redistribution when GTI unavailable
- **Requirement 15.3-15.4**: Distinguish budget exhaustion from circuit breaker degraded mode

### 6. Circuit Breaker Remains Unchanged
The existing circuit breaker (5 consecutive failures → degraded mode) continues to handle **service failures** (timeouts, API errors), which is distinct from budget exhaustion. When the circuit breaker triggers, it also applies the 0.2 penalty and weight redistribution, but additionally disables all GTI queries until the 60-second cooldown completes.

## Consequences

### Pros:
- **Cost-Effective**: Blackwall can operate indefinitely on VirusTotal free tier without hitting rate limits during normal operation
- **Performance**: Primary defense (local SQLite + YAML + CBM) provides <10ms blocking decisions without external API dependency
- **Resilience**: System remains fully functional when GTI budget exhausted or service unavailable
- **Intelligent Prioritization**: Suspicion scoring ensures the most critical events get GTI validation within budget constraints
- **Graceful Degradation**: Automatic weight redistribution maintains threat score accuracy when GTI unavailable
- **Clear Separation**: Budget exhaustion (transient, self-healing) is architecturally distinct from service failure (circuit breaker)

### Cons:
- **Reduced GTI Coverage**: Only ~4 events per minute receive GTI validation (vs. originally envisioned 300 RPM)
- **Delayed Zero-Day Detection**: Novel threats not yet in local signatures may be missed if not classified as high-risk
- **Complexity**: Suspicion scoring and prioritization logic adds implementation complexity
- **Cache Dependency**: 24-hour TTL caching becomes critical to maximize budget utilization
- **Judge Reproduction**: Kaggle judges may see different GTI query patterns depending on attack timing and budget state

### Mitigations:
- **Self-Learning Signatures**: When GTI does validate a malicious IOC, the threat signature is permanently cached locally, enabling future instant detection without GTI queries
- **24-Hour Cache TTL**: Repeated IOCs (e.g., same C2 IP across multiple attacks) only consume 1 GTI query per day
- **High Cache Hit Rate Target**: >60% cache hit rate reduces effective GTI query consumption
- **Documentation**: README and JUDGE_EVALUATION.md clearly document the 4/min constraint and how it affects demo behavior
- **Metrics Transparency**: `BudgetMetrics` tracks queries attempted vs. executed, making budget exhaustion visible to judges

### Future Considerations:
If the project receives funding post-hackathon:
- Premium VirusTotal tier could be evaluated (though $1,600/month remains expensive)
- Alternative threat intelligence APIs with more generous free tiers could supplement GTI
- Local threat intelligence databases (e.g., AlienVault OTX, abuse.ch) could be integrated as additional secondary validators

## Related Documents
- **Requirements**: Requirement 9 (GTI Integration), Requirement 5 (Hybrid Policy Server), Requirement 15 (Error Handling)
- **Design**: Component 6.5 (GTI Query Budget Tracker), Component 7 (GTI MCP Integration)
- **Tasks**: Task 7.1 (GTI Client with budget awareness), Task 7.3 (Budget Tracker implementation), Task 9.1 (Semantic Gating with budget checking)


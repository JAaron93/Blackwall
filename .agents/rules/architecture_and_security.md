# Architectural, Database, & Security Rules

## 1. DSN & Credential Log Sanitization Hygiene
* **Rule:** Log messages MUST NEVER include raw DSN connection strings (`self.dsn`), URLs containing embedded credentials, or raw authentication keys. Omit DSN parameters or log sanitized host/port strings to prevent credential exposure in failure logs.
* **Rationale:** In failure scenarios, logs are widely captured and shared across SOC systems. Including DSNs or URLs with embedded credentials leaks database passwords into log streams.

## 2. Atomic Database Transactions & Cache Synchronization
* **Rule:** Store modules persisting data across both a database backend (e.g. PostgreSQL via `asyncpg`) and an in-memory cache MUST wrap database persistence statements in an explicit transaction (`async with conn.transaction():`), and mutate in-memory cache structures ONLY after successful DB commit. Re-ingesting duplicate items (e.g. `ON CONFLICT DO NOTHING`) MUST preserve existing cached edge/relationship lists.
* **Rationale:** Non-atomic operations leave in-memory caches and database tables out of sync during transient network failures, corrupting graph edge relationships.

## 3. Explicit Connection Error Escalation
* **Rule:** Persistent store initialization methods MUST NOT silently degrade to in-memory mode when an explicit connection DSN is provided and `in_memory=False`. Database connection exceptions MUST be raised to signal non-durable state to callers.
* **Rationale:** Silently falling back to in-memory storage hides infrastructure misconfigurations and leads to data loss upon process restarts.

## 4. Production Import Error Enforcement
* **Rule:** Module entrypoints (`agent/__init__.py`, `blackwall/__init__.py`) MUST NOT swallow missing configuration `ValueError` exceptions in production. Exception suppression is permitted ONLY when `PYTEST_CURRENT_TEST` or `BLACKWALL_TEST_MODE` is present in `os.environ`.
* **Rationale:** Suppressing configuration errors in production allows daemons to launch in invalid or unmonitored security states.

## 5. Unconditional Credential Purging
* **Rule:** Provider configuration helpers (`configure_provider_env()`) MUST purge legacy API keys (`GEMINI_API_KEY`, `LLM_API_KEY`) and re-assert required mode variables (`GOOGLE_GENAI_USE_VERTEXAI="true"`, `GEMINI_TIER="paid"`) on *every* call, regardless of module-level caching flags.
* **Rationale:** Prevents credential leakage and ensures GCP Vertex AI enterprise mode compliance across all sub-processes.

## 6. Context Hygiene & Sanitization
* **Rule:** `ContextResolver` middleware must replace sensitive environment variable patterns with generic placeholders (`[[VARIABLE_NAME]]`). Integration tests querying external hostnames (e.g. GTI / VirusTotal) must use un-redacted standalone hostnames (e.g. `wd-bouygues.com`) to prevent accidental sanitization matching.

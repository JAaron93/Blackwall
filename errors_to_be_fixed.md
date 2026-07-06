```
You are a software engineer working on the Blackwall Agentic Firewall project. The webhook listener implementation has three critical bugs that need to be corrected. Your job is to fix `src/blackwall/api/webhook_listener.py` and `tests/unit/test_webhook.py` so they conform to the architecture spec.

---

## The Three Bugs

### Bug 1: Wrong signature verification method

**Current behaviour:** The code uses `hmac.new(secret_key, payload, sha256)` to verify an `X-Webhook-Signature` header, and returns `401 Unauthorized` on failure.

**Correct behaviour:** Gemini Dynamic Webhooks use **JWT/JWKS asymmetric signature verification (RS256)**, not HMAC-SHA256. The correct flow is:
1. Extract the JWT from the `Webhook-Signature` header (not `X-Webhook-Signature`).
2. Decode the JWT header (without verification) to get the `kid` field.
3. Fetch the RSA public key from Google's JWKS endpoint: `https://generativelanguage.googleapis.com/.well-known/jwks.json`, matching on `kid`.
4. Verify the JWT's RS256 signature using the fetched public key, and validate the `audience` claim.
5. On failure, return `400 Bad Request` (not `401`).
6. Cache the JWKS keys in memory (TTL: 1 hour) to avoid fetching on every request.

Use `PyJWT` with `cryptography` for JWT decoding/verification, and `aiohttp` for the JWKS fetch. The `BLACKWALL_WEBHOOK_SECRET` env var is no longer used for signature verification and can be removed from the constructor. The JWKS endpoint URL should be configurable via `GEMINI_JWKS_URL` env var with the default above.

---

### Bug 2: Wrong HTTP response status

**Current behaviour:** On success the endpoint returns `202 Accepted`.

**Correct behaviour:** Return `200 OK`. The spec requires `200 OK` within <50ms of receipt. Update all occurrences in both the implementation and the tests.

---

### Bug 3: Wrong payload model — fat payload vs thin payload

**Current behaviour:** `_process_payload()` extracts `task_id` and `threat_signature_candidates` directly from the webhook body, treating it as a fat payload containing full analysis results.

**Correct behaviour:** Gemini uses a **thin-payload Standard Webhooks envelope**. The webhook body only contains:
```json
{
  "type": "interaction.completed",
  "version": "1",
  "timestamp": "<ISO 8601>",
  "data": {
    "id": "<interaction_id>"
  }
}
```

It does NOT contain analysis results inline. The correct processing flow is:
1. Extract `interaction_id` from `payload["data"]["id"]`.
2. Validate `webhook-timestamp` header — reject payloads where the timestamp is older than 5 minutes (return `400 Bad Request`).
3. Deduplicate using the `webhook-id` header — if this `webhook-id` has already been processed (check a small in-memory set or SQLite), log and return `200 OK` without reprocessing.
4. Immediately return `200 OK` to Gemini.
5. In the background task: call `await gemini_client.interactions.get(interaction_id)` to fetch the full interaction output.
6. Pass the fetched output to `Agent_Behavioral_Analytics.generateSignature()` to derive threat signatures.

The `WebhookListener.__init__` constructor must accept a `gemini_client` parameter (the existing `google.genai` client instance) alongside `db_repository`.

The OpenTelemetry span should include `interaction_id`, `webhook_latency_ms` (time from webhook receipt to 200 response), and `fetch_latency_ms` (time for `interactions.get()` to return), plus the existing `signatures_created_count`.

---

## What to preserve

- The `aiohttp` web framework and application structure.
- The `asyncio.create_task` fire-and-forget pattern for background processing.
- The 30-second graceful shutdown drain in `stop()`.
- The structlog/standard logging setup.
- The OpenTelemetry span structure (update attribute names as described above, don't remove instrumentation).
- The WAL-mode SQLite `db_repository` usage.

---

## Test file changes required

Rewrite `tests/unit/test_webhook.py` to match the corrected implementation:

1. Remove all HMAC imports (`hmac`, `hashlib`) and helper methods (`generate_signature`).
2. Remove `BLACKWALL_WEBHOOK_SECRET` env var setup.
3. Add a fixture that mocks `aiohttp.ClientSession.get` to return a fake JWKS response with a test RSA key pair.
4. Add a fixture that generates a valid test JWT signed with the test RSA private key (RS256), with the correct `audience` and `kid` matching the mocked JWKS.
5. Replace all `X-Webhook-Signature: <hmac>` header construction with `Webhook-Signature: <jwt>`.
6. Replace all `status=401` assertions with `status=400`.
7. Replace all `status=202` assertions with `status=200`.
8. Replace fat payload construction (`task_id`, `threat_signature_candidates`) with the thin envelope format (`type`, `version`, `timestamp`, `data.id`).
9. Add a test verifying `client.interactions.get(interaction_id)` is called after webhook receipt.
10. Add a test verifying replay rejection: sending a `webhook-timestamp` header more than 5 minutes in the past returns `400`.
11. Add a test verifying duplicate `webhook-id` is silently discarded (returns `200` but does not write signatures twice).
12. Add a test verifying a JWT with invalid signature returns `400`.
13. Add a test verifying a JWT with wrong audience returns `400`.
14. Existing tests for stale/unknown task_id, atomic writes, and graceful shutdown should be adapted to use the new thin-payload flow (mock `gemini_client.interactions.get()` to return a fake interaction result).

---

## Required dependencies

Add to `pyproject.toml` if not already present:
- `PyJWT>=2.8.0`
- `cryptography>=42.0.0`

---

## Acceptance criteria (run these to verify correctness)

```bash
pytest tests/unit/test_webhook.py -v
```

All tests must pass. No test should use HMAC, `X-Webhook-Signature`, status 401, status 202, or inline `threat_signature_candidates` in the webhook payload body.
```
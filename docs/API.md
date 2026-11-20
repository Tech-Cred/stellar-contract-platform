# REST API

The Observatory exposes its contract-intelligence services over a versioned REST
API. The API is a thin transport over the same services the CLI uses; it performs
no analysis of its own.

- Base path: `/api/v1`
- Content type: `application/json` (Prometheus text exposition for
  `GET /api/v1/metrics`)
- Transport: a minimal bounded HTTP/1.1 adapter (`observatory-api::http`)
- OpenAPI: `stellar-contract-platform api openapi`

## Running locally

```bash
# Read-only dev server with authentication disabled
stellar-contract-platform api serve --bind 127.0.0.1:8080 --no-auth

# With authentication and a pre-registered key
stellar-contract-platform api serve --bind 127.0.0.1:8080 \
  --key developer:sco_<id>_<secret>
```

> The bundled HTTP adapter is intended for local and test use. It is bounded and
> deterministic but is not a hardened edge server.

## Authentication

Analysis endpoints require an API key, supplied either as a bearer token or a
header:

```
Authorization: Bearer sco_<id>_<secret>
X-API-Key: sco_<id>_<secret>
```

Keys are random; only a SHA-256 hash is stored, and the hash is never returned.
The plaintext is shown exactly once at creation. The default store is in memory;
a `FileKeyStore` persists only ids, hashes, roles, labels, and revocation state,
so keys survive a restart without ever writing the plaintext to disk.

| Status | Body `code` | Meaning |
| ------ | ----------- | ------- |
| 401 | `unauthorized` | Missing or invalid key |
| 403 | `forbidden` | Key lacks the required permission |

## Authorization

Roles are hierarchical. Each endpoint requires a permission.

| Role | Permissions |
| ---- | ----------- |
| `viewer` | `read_health`, `read_version` |
| `developer` | viewer + `run_analysis` |
| `maintainer` | developer + `manage_webhooks` |
| `admin` | maintainer + `manage_keys` |

Analysis endpoints require `run_analysis`. `GET /health`, `/readiness`,
`/version`, and `/metrics` are public. Metrics expose only aggregate counters,
never endpoints, keys, or payloads.

## Rate limiting

Fixed-window, keyed by API-key id (or client IP when unauthenticated) **and** the
request path, so every endpoint has its own window.

```
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 119
X-RateLimit-Reset: 60
```

Exceeding the limit returns `429` with `code: "rate_limited"`. The default is
`PlatformConfig.rate_limit`. A stricter limit for one route does not affect the
others: set `PlatformConfig.route_limits["<exact path>"]` (or
`api.route_limits` in the project file). The headers always report the effective
limit for the request's route.

## Request IDs

Every response carries `X-Request-Id`, a stable identifier for correlation.

## Endpoints

### `GET /api/v1/health` (public)
`{ "schema_version", "kind": "health", "tool", "version", "data": { "status": "ok" } }`

### `GET /api/v1/readiness` (public)
Reports readiness and whether authentication is required.

### `GET /api/v1/version` (public)
Tool version, schema version, and API version.

### `GET /api/v1/metrics` (public)
Aggregate request counters in the Prometheus text exposition format
(`text/plain; version=0.0.4`):

```text
# HELP observatory_api_requests_total Total HTTP requests handled.
# TYPE observatory_api_requests_total counter
observatory_api_requests_total 42
```

`?format=json` returns the same counters in the standard report envelope:

```json
{ "schema_version": "1.0", "kind": "metrics", "tool": "stellar-contract-platform", "version": "0.1.0", "data": { "requests_total": 42, "analyses_total": 7, "errors_total": 3, "rate_limited_total": 0 } }
```

Counters are process-local and monotonic. They cover every handled request,
successful contract analyses, responses with a `4xx`/`5xx` status, and requests
rejected by the rate limiter. The exposition is deterministic and contains no
secrets.

### `POST /api/v1/keys` (admin)

Creates an API key. Requires `manage_keys`.

Body: `{ "role": "viewer|developer|maintainer|admin", "label": "ci" }`.

The response (`201`) contains the plaintext exactly once. It is never retrievable
again, and listing never returns it. The response also includes the key id, role,
and label.

```json
{ "schema_version": "1.0", "kind": "api_key", "tool": "stellar-contract-platform", "version": "0.1.0", "data": { "id": "...", "role": "developer", "label": "ci", "plaintext": "sco_...", "note": "the plaintext key is shown once and cannot be retrieved again" } }
```

### `GET /api/v1/keys` (admin)

Lists key metadata (id, role, label, revocation state). Requires `manage_keys`.
Hashes, secrets, and plaintext are never included.

```json
{ "schema_version": "1.0", "kind": "api_keys", "tool": "stellar-contract-platform", "version": "0.1.0", "data": { "keys": [ { "id": "...", "role": "developer", "label": "ci", "revoked": false } ] } }
```

### `DELETE /api/v1/keys/{id}` (admin)

Revokes a key. Requires `manage_keys`. Revocation takes effect immediately; the
next request with that key receives `401`. An unknown id returns `404`.

### `POST /api/v1/contracts/inspect`
Body: `{ "wasm_base64": "...", "security": false }`.
Returns the WASM report, the canonical interface (when present), and the audit
(when `security` is true).

### `POST /api/v1/contracts/spec`
Body: `{ "wasm_base64": "..." }`. Returns the normalized spec and its summary.

### `POST /api/v1/contracts/diff`
Body: `{ "old_wasm_base64": "...", "new_wasm_base64": "..." }`. Returns the
interface diff.

### `POST /api/v1/contracts/compatibility`
Body: `{ "old_wasm_base64": "...", "new_wasm_base64": "...", "policy": "strict" }`.
Returns the compatibility assessment. `policy` is `strict` (default) or
`lenient`.

### `POST /api/v1/contracts/fingerprint`
Body: `{ "wasm_base64": "..." }`. Returns artifact and interface fingerprints.

### `POST /api/v1/contracts/security`
Body: `{ "wasm_base64": "..." }`. Returns bounded heuristic findings.

## Webhook delivery

`observatory-platform::webhook::deliver` signs an event and delivers it with
bounded retries; registration endpoints are tracked separately in issue #47.

- The signature is HMAC-SHA256 over `<timestamp>.<body>`.
- Every attempt carries `X-Observatory-Signature: sha256=<hex>`,
  `X-Observatory-Timestamp`, `X-Observatory-Event`, and a stable
  `X-Observatory-Delivery-Id` for replay protection.
- Transient failures (`408`, `429`, `5xx`, and transport errors) are retried with
  exponential backoff up to a cap. Other `4xx` responses are not retried.
- The returned `DeliveryOutcome` records every attempt, the final status, and the
  last status or error.

See [webhooks.md](webhooks.md) for the verification steps.

## Response envelope

Success:

```json
{ "schema_version": "1.0", "kind": "inspect", "tool": "stellar-contract-platform", "version": "0.1.0", "data": { } }
```

Error:

```json
{ "schema_version": "1.0", "kind": "error", "code": "bad_request", "message": "..." }
```

RPC failures additionally include the typed kind and preserved raw code:

```json
{ "schema_version": "1.0", "kind": "error", "code": "rpc", "message": "...", "rpc_kind": "method_not_found", "rpc_code": -32601 }
```

See [`rpc-errors.md`](rpc-errors.md) for the full taxonomy.

## Status codes

| Status | Meaning |
| ------ | ------- |
| 200 | success |
| 201 | resource created (API key) |
| 400 | invalid request or artifact |
| 401 | authentication required or invalid |
| 403 | authenticated but not permitted |
| 404 | unknown route |
| 405 | method not allowed for a known route |
| 413 | request body too large |
| 415 | non-JSON content type |
| 422 | unsupported feature |
| 429 | rate limited |
| 500 | internal error |
| 502 | upstream RPC error |

## OpenAPI synchronization

`observatory-api::openapi::document()` is generated from the single route table
and a test asserts every route is documented and vice versa, so the
specification cannot silently drift.

## Not included

- Webhook management endpoints (registration is tracked in #47). The signed
  delivery engine is implemented in `observatory-platform`.
- Deployment/verification endpoints over live RPC (blocked on the live
  transport, issue #13).
- Persistence of users or audit events. API-key persistence is available through
  `FileKeyStore`; the default remains in memory.

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
The plaintext is shown exactly once at creation.

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

## CORS

Cross-origin access is denied by default. Configure exact origins through
`PlatformConfig.cors` or the project file (`api.cors`). Allowed origins are
echoed in `Access-Control-Allow-Origin`; disallowed origins receive no CORS
headers. Preflight (`OPTIONS`) requests from allowed origins return `204` with
`Access-Control-Allow-Methods` and `Access-Control-Allow-Headers`. Credentials
are never enabled, so a wildcard origin cannot be combined with cookies.

## HTTP adapter limits

The bundled adapter enforces configurable read/write timeouts, a bounded
concurrent connection count (excess connections receive `503`), and bounded
request-line, header-line, header-count, and body sizes. Every limit is a CLI
flag (`api serve --max-connections 64 --read-timeout-secs 10 ...`) and mirrors
`observatory_api::http::HttpLimits`.

## Rate limiting

Fixed-window, keyed by API-key id (or client IP when unauthenticated).

```
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 119
X-RateLimit-Reset: 60
```

Exceeding the limit returns `429` with `code: "rate_limited"`. Limits are
configurable via `PlatformConfig` (`rate_limit.limit`, `rate_limit.window_secs`).

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

### `POST /api/v1/contracts/events`
Fixture-backed event query. Body:

```json
{
  "fixture": { "events": [ ... ] },
  "contract": "C...",
  "topic": "transfer",
  "type": "contract",
  "limit": 100
}
```

`fixture` accepts the same shapes as the CLI (an array, an object with an
`events` array, a raw event object, or a base64 `ContractEvent`). Filters are
applied in the order contract, type, topic, then limit. `limit` defaults to 100
and is bounded to 1000. Malformed fixtures return a structured `400`.

### `GET /api/v1/jobs` and `POST /api/v1/jobs`
In-process background jobs for long-running work. Enqueue with:

```json
{ "kind": "analysis", "idempotency_key": "optional", "max_attempts": 3 }
```

Repeating an `idempotency_key` returns the existing job. `GET /api/v1/jobs`
lists jobs; `GET /api/v1/jobs?id=<id>` returns one job. States are `queued`,
`running`, `succeeded`, `failed`, and `cancelled`. Concurrency is bounded and
failures are recorded and retried up to `max_attempts`.

### `POST /api/v1/jobs/cancel`
Body `{ "id": "job-..." }`. Only queued jobs can be cancelled; anything else
returns a structured `400`.

### `GET /api/v1/audit/events`
Requires `manage_keys` (admin). Returns structured audit events with
`schema_version`, `timestamp`, `actor` (public key id), `action`, `resource`,
`outcome`, and `request_id`. Secrets and plaintext keys are never recorded.
### Webhook subscriptions

Webhook registration requires `manage_webhooks` (the `maintainer` or `admin`
role). URLs must use `https` and must not embed credentials.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `POST` | `/api/v1/webhooks` | Register a subscription |
| `GET` | `/api/v1/webhooks` | List subscriptions |
| `GET` | `/api/v1/webhooks/{id}` | Read a subscription |
| `PATCH` | `/api/v1/webhooks/{id}` | Update URL, events, or active state |
| `DELETE` | `/api/v1/webhooks/{id}` | Delete a subscription |

Create body: `{ "url": "https://example.com/hook", "events": ["analysis_completed"] }`.
Supported events are `analysis_completed`, `analysis_failed`, and
`deployment_verified`. The response includes a random `secret` exactly once; it
is never returned by list or get.

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

Every `POST` route publishes a concrete request schema (`InspectRequest`,
`WasmRequest`, `DiffRequest`, `CompatibilityRequest`, `EventsRequest`,
`CreateJobRequest`, `CancelJobRequest`) instead of a generic object. Each schema
is closed to unknown fields and declares its required inputs; tests assert the
references and required fields stay in sync.

## Client SDKs

Typed Rust and TypeScript clients live under `crates/observatory-client` and
`sdks/typescript`; see [`sdk.md`](sdk.md).

## Not included

- Deployment/verification endpoints over live RPC (blocked on the live
  transport, issue #13).
- Durable persistence of keys, users, webhooks, jobs, or audit events across
  restarts (the in-process stores are bounded and reset with the process).

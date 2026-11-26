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

A key may optionally carry `scopes`: a subset of its role's permissions. An
absent scope list grants the full role, so existing keys are unchanged. A scoped
key is authorized only for the intersection of its role and its scopes. Unknown
scope names, and scopes the role does not grant, are rejected when the key is
created.

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

## Idempotency

Mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`) may carry an
`Idempotency-Key` header (1-255 bytes). The first successful (`2xx`) response is
cached for 300 seconds and replayed for an identical request; a replay carries
`Idempotency-Replayed: true`.

- Reusing a key with a different method, path, query, or body returns `409` with
  `code: "idempotency_conflict"`.
- Keys are scoped to the caller (API-key id, or client IP when unauthenticated),
  so two clients can use the same key independently.
- Only successful responses are cached; a failed request can be retried with the
  same key.
- The cache holds at most 128 responses and evicts the oldest entry, so unique
  keys cannot grow memory without bound.
- Without the header, requests behave exactly as before and are never cached.

## Request IDs

Every response carries `X-Request-Id`, a stable identifier for correlation.

## Pagination

The list endpoints are paginated with the optional `limit` and `cursor` query
parameters:

- `GET /api/v1/jobs` (list mode), `GET /api/v1/keys`, `GET /api/v1/webhooks`,
  and `GET /api/v1/audit/events`.

`limit` is an integer between 1 and 1000 and defaults to 100. Pages are taken
over each endpoint's deterministic order: jobs, keys, and webhooks are
id-ordered, and audit events are oldest-first. Every page response carries a
`Page` object in the envelope's `data`:

```json
{
  "items": [ { "id": "job-0000000000000001" } ],
  "count": 1,
  "has_more": false,
  "next_cursor": null
}
```

`has_more` is true exactly when `next_cursor` is non-null. Pass the previous
page's `next_cursor` back as the `cursor` query parameter to fetch the next
page. A malformed `limit` or `cursor` returns a structured `400`
(`bad_request`).

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
Body: `{ "role": "viewer|developer|maintainer|admin", "label": "ci", "scopes": ["run_analysis"] }`.
`scopes` is optional; when present it must be a subset of the role's permissions.
The response (`201`) contains the plaintext exactly once; listing never returns it.

### `GET /api/v1/keys` (admin)
Lists key metadata (id, role, label, revocation state) as a paginated
[`Page`](#pagination). Requires `manage_keys`. Hashes, secrets, and plaintext
are never included.

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
Returns the compatibility assessment. `policy` is `strict` (default),
`additive-only`, or `lenient`; `additive-only` accepts additions and treats
removals, renames, and modifications as breaking.

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
lists jobs as a paginated [`Page`](#pagination); `GET /api/v1/jobs?id=<id>`
returns one job. States are `queued`, `running`, `succeeded`, `failed`, and
`cancelled`. Concurrency is bounded and failures are recorded and retried up
to `max_attempts`.

### `POST /api/v1/jobs/cancel`
Body `{ "id": "job-..." }`. Only queued jobs can be cancelled; anything else
returns a structured `400`.

### `GET /api/v1/audit/events`
Requires `manage_keys` (admin). Returns structured audit events with
`schema_version`, `timestamp`, `actor` (public key id), `action`, `resource`,
`outcome`, and `request_id`, paginated as a [`Page`](#pagination). Events are
redacted with the standard secret-redaction pass, so they contain no secrets;
key ids, job ids, and paths remain readable. The log itself is built to carry
no secrets, and secrets and plaintext keys are never recorded.
### Webhook subscriptions

Webhook registration requires `manage_webhooks` (the `maintainer` or `admin`
role). URLs must use `https` and must not embed credentials.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `POST` | `/api/v1/webhooks` | Register a subscription |
| `GET` | `/api/v1/webhooks` | List subscriptions (paginated) |
| `GET` | `/api/v1/webhooks/{id}` | Read a subscription |
| `PATCH` | `/api/v1/webhooks/{id}` | Update URL, events, or active state |
| `DELETE` | `/api/v1/webhooks/{id}` | Delete a subscription |

Create body: `{ "url": "https://example.com/hook", "events": ["analysis_completed"] }`.
Supported events are `analysis_completed`, `analysis_failed`, and
`deployment_verified`. The response includes a random `secret` exactly once; it
is never returned by list or get.

### Signed webhook delivery

`observatory_platform::deliver` signs an event and delivers it with bounded
retries. The signature is HMAC-SHA256 over `<timestamp>.<body>`, sent as
`X-Observatory-Signature: sha256=<hex>` with `X-Observatory-Timestamp`,
`X-Observatory-Event`, and a stable `X-Observatory-Delivery-Id`. Transient
failures (`408`, `429`, `5xx`, and transport errors) are retried with
exponential backoff; other `4xx` responses are not. See
[webhooks.md](webhooks.md) for verification steps.

## API versioning and deprecation

The API version is the path segment: requests are served under `/api/v1`, and
`GET /api/v1/version` reports it as `api_version: "v1"`. The version covers the
route set, request and response shapes, authentication requirements, status
codes, and the meaning of a successful response.

### Adding changes

Additive changes ship within the current version. Examples are a new route, a
new response field, or a new optional request field. Consumers must ignore
response fields they do not recognise; request schemas still reject unknown
fields, so new request fields are only compatible when they are optional.

A change is breaking when it removes or renames a route or field, changes a
field's type or the status code for an existing outcome, tightens
authentication or validation, or changes what an existing response means. A
breaking change requires a new API version (for example `/api/v2`). The previous
version is not changed to accommodate it.

### Deprecating and retiring

A version is deprecated before it is retired:

1. Deprecation is announced in this document and in `CHANGELOG.md`. The
   announcement names the version being replaced, the replacement version, and
   the routes or behaviours that change.
2. The deprecated version continues to serve requests for at least one minor
   tool release after the announcement, so consumers have a release cycle to
   migrate.
3. Retirement removes the version from the route table. Requests to a retired
   version return `404`, and the version no longer appears in the OpenAPI
   document.

No calendar dates are promised. A version is retired only after the notice in
step 1 and the overlap in step 2 have both happened. This policy can change, but
a change that shortens notice is itself a breaking change and is documented the
same way.

### Relationship to `schema_version`

`api_version` and `schema_version` are independent:

- `api_version` selects the HTTP surface: routes, request bodies, and status
  codes.
- `schema_version` identifies the JSON report envelope and payload schemas. It
  currently is `1.0` and appears in every success and error report.

A new API version may keep the same `schema_version` when the report shapes do
not change. A `schema_version` change does not by itself require a new API
version when the route surface is unchanged. Consumers that parse reports should
pin both values. The schemas are published under `docs/schemas/`; see
[`schemas/README.md`](schemas/README.md).

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
| 204 | no content (CORS preflight) |
| 400 | invalid request or artifact |
| 401 | authentication required or invalid |
| 403 | authenticated but not permitted |
| 404 | unknown route or resource |
| 405 | method not allowed for a known route |
| 413 | request body too large |
| 415 | non-JSON content type |
| 422 | unsupported feature or failed verification |
| 429 | rate limited |
| 500 | internal error |
| 502 | upstream RPC error |
| 503 | server at its connection limit |

## Error catalog

`GET /api/v1/errors` publishes every error code the API can emit. It requires no
authentication and is generated from the same catalog that builds error
responses, so a code's status cannot drift between the response and the
catalog. Each entry has `code`, `status`, `description`, and `retryable`:

```json
{
  "schema_version": "1.0",
  "kind": "errors",
  "data": {
    "errors": [
      { "code": "rate_limited", "status": 429, "description": "The caller exceeded its rate limit; retry after the reset window.", "retryable": true }
    ]
  }
}
```

`retryable` means retrying the same request may succeed (for example after a
rate-limit reset or an upstream RPC failure). Client errors such as
`bad_request` are not retryable without changing the request. The catalog also
appears in the OpenAPI document `GET /api/v1/errors` operation.

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
- Persistence of users, webhooks, jobs, or audit events across restarts.
  API-key persistence is available through `FileKeyStore`; the default remains
  in memory.

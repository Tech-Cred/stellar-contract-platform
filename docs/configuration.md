# Configuration

Projects can declare defaults in a configuration file. Flags always win over the
file, and the file wins over built-in defaults.

## Discovery and selection

The CLI loads a configuration file from the current directory if one exists, in
this priority order:

1. `observatory.yml`
2. `observatory.yaml`
3. `observatory.toml`
4. `observatory.json`

Use `--config <FILE>` to point at a specific file. The format is inferred from
the extension. Parsing is **strict**: unknown fields are rejected so a typo does
not silently disable a setting.

## Per-network profiles

A profile bundles overrides for one network. Declare them under `profiles`,
keyed by network name (`public`, `testnet`, or `futurenet`), and select one with
`--profile <NAME>` or the top-level `profile` field. The flag wins over the
field. Profiles are validated while the file is parsed: a key that is not a
known network, an unknown `policy`, or an invalid `endpoint` is an error.

## Schema

```yaml
project:
  name: my-project
  network: testnet        # default network for verify/deployment

analysis:
  compatibility:
    policy: strict        # strict | lenient

rpc:
  endpoint: https://soroban-testnet.stellar.org
  connect_timeout_secs: 10   # default: 10
  read_timeout_secs: 30      # default: 30
  max_response_bytes: 8388608  # default: 8 MiB; must be > 0

api:
  require_auth: true
  rate_limit:
    limit: 120
    window_secs: 60
  route_limits:
    /api/v1/contracts/inspect:
      limit: 10
      window_secs: 60
  cors:
    allowed_origins:
      - https://app.example.com
    allowed_methods: [GET, POST, PATCH, DELETE]
    allowed_headers: [content-type, authorization, x-api-key]

audit:
  enabled:                # default: all non-experimental rules
    - spec.error
    - artifact.no-code
  severity:
    artifact.no-code: ERROR

ci:
  fail_on: MISMATCH       # statuses that should fail a build

profile: testnet          # profile selected when --profile is omitted

profiles:
  testnet:
    endpoint: https://soroban-testnet.stellar.org
    policy: lenient
  public:
    policy: strict
```

The same content is valid TOML or JSON. Example TOML:

```toml
[project]
network = "testnet"

[analysis.compatibility]
policy = "lenient"

[api]
require_auth = false

[api.rate_limit]
limit = 60
window_secs = 30

[api.route_limits."/api/v1/contracts/inspect"]
limit = 10
window_secs = 60
```

## What the file affects

| Field | Effect |
| ----- | ------ |
| `project.network` | Default network for `verify` and `deployment` when `--network` is omitted. |
| `analysis.compatibility.policy` | Default policy for `compat` when `--policy` is omitted. |
| `api.require_auth` | Default authentication requirement for `api serve`. |
| `api.rate_limit` | Default rate limit for `api serve`. |
| `api.route_limits` | Per-route rate-limit overrides, keyed by exact request path. Unlisted routes use `api.rate_limit`. |
| `api.cors` | Cross-origin allow-list for `api serve`; empty denies all origins. |
| `audit.enabled` | Rule allow-list for `inspect --security`; defaults to every non-experimental rule. |
| `audit.severity` | Per-rule `WARN`/`ERROR` overrides for `inspect --security`. |
| `rpc.endpoint` | Default endpoint for `deployment inspect` when neither `--rpc-url` nor a profile overrides it. Validated and recorded; live transport is future work. |
| `rpc.connect_timeout_secs` | Connect timeout for RPC requests; defaults to 10 seconds. Zero is rejected. |
| `rpc.read_timeout_secs` | Read timeout for RPC response headers and body; defaults to 30 seconds. Zero is rejected. |
| `profiles.<network>.endpoint` | Endpoint override when that profile is selected. |
| `profiles.<network>.policy` | Compatibility-policy override when that profile is selected. |
| `profile` | Profile used when `--profile` is omitted. |
| `ci.fail_on` | Comma-separated verification statuses that fail the build: `MISMATCH`, `INSUFFICIENT_DATA`, `ERROR`. Defaults to all three. |

## Precedence

1. Explicit CLI flags, including `--profile`, (highest)
2. The selected profile's overrides
3. `--config` file, or a discovered file
4. Built-in defaults (lowest)

## Validation

Everything is validated while the file is parsed, before any command runs.

- Unknown top-level or nested fields are errors.
- An unknown `analysis.compatibility.policy` is an error.
- `project.network` must be a known network (`public`, `testnet`, or `futurenet`).
- `rpc.endpoint` must be a valid `https` endpoint (loopback `http` is allowed).
- A profile key that is not a known network name is an error.
- A profile `policy` other than `strict` or `lenient` is an error.
- A profile `endpoint` must be a valid `https` endpoint (loopback `http` is allowed).
- Selecting an unknown profile is an error.
- An unknown `audit.enabled` or `audit.severity` rule id is an error.
- A `ci.fail_on` status other than `MISMATCH`, `INSUFFICIENT_DATA`, or `ERROR`
  is an error; `MATCH` is rejected.
- An unsupported file extension is an unsupported-feature error (exit code `5`).

`analysis.compatibility.policy` accepts the `strict`, `additive-only`, and
`lenient` presets.
For individual rule settings, pass a separate policy document to
`compat --policy-file <FILE>`; see [compatibility.md](compatibility.md).

## Not included

Live environment-variable overrides are not implemented yet; `rpc.endpoint` is
recorded and validated but the shipped verify/deployment commands still read
deployed state only through RPC fixtures.

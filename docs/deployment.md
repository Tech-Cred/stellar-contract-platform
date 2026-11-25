# Deployment inspection

`deployment inspect` looks up a deployed contract's instance entry and recovers
the executable WASM hash.

> To run the REST API itself as a container, see
> [container-image.md](container-image.md).

## How it works

1. The contract id (`C...` strkey) is decoded to its 32-byte hash.
2. A `LedgerKey::ContractData` key is built with `LedgerKeyContractInstance`.
3. `getLedgerEntries` is called through the configured transport.
4. The returned `LedgerEntryData` XDR is decoded; a WASM-backed instance yields
   `ContractExecutable::Wasm(hash)`, which is reported as hex.

Nothing about the RPC shape is invented; the key and entry are real Stellar XDR
types.

## Transports

The core does not hard-code a provider. Deployment uses the `Transport`
abstraction. This build ships a deterministic **fixture transport** in the CLI;
the library also provides an opt-in live HTTPS transport.

```bash
stellar-contract-platform deployment inspect C... \
  --rpc-fixture rpc.json --network testnet
```

### Network profiles

`--network` is resolved to a `NetworkProfile` in `observatory-core`: the
canonical name, the network passphrase and a default RPC endpoint. Accepted
labels are `public` (also `mainnet`, `pubnet`), `testnet` (also `test`) and
`futurenet` (also `future`); any other label is rejected before the lookup.

`inspect` records the resolved profile in its output as `network`, with the
name, passphrase and default endpoint. When neither `--rpc-url` nor the project
config sets an endpoint, the profile's default endpoint is used and validated.
The fixture transport makes no requests, so that endpoint is recorded but not
called. Library callers get the same record from `inspect_on_network`.

### Live HTTPS transport

`observatory_rpc::HttpTransport` implements `Transport` over HTTPS. It is behind
the `observatory-rpc` crate feature `live`, which is off by default:

```toml
observatory-rpc = { path = "crates/observatory-rpc", features = ["live"] }
```

`HttpTransport::new(endpoint)` rejects anything `Endpoint::parse` rejects, then
applies the SSRF policy before every request. See
[endpoint validation and trust](#endpoint-validation-and-trust) for the exact
rules and examples. The transport never follows redirects, ignores environment
proxies, applies a 30-second request timeout, and caps a response body at 8 MiB;
`with_limits` overrides both limits. Failures are reported as typed RPC errors
that name the endpoint host, without echoing the URL or credentials.

The CLI does not switch to the live transport in this build; commands continue
to require a fixture. Wiring the transport into `deployment` and `verify` is
tracked separately.

## Endpoint validation and trust

Endpoint strings are validated by `observatory_rpc::Endpoint::parse`. The
platform config runs that validation when it loads `rpc.endpoint` and every
`profiles.<name>.endpoint`, so a bad value fails before any analysis starts. The
CLI validates `--rpc-url` the same way. `HttpTransport::new` parses the endpoint
again, and every `send` re-parses it and re-applies the SSRF policy before
connecting. This section is split into the URL rules (always enforced) and the
address policy (applied by the live transport).

### URL rules

`Endpoint::parse` enforces all of the following:

- The input must not be empty after trimming surrounding whitespace.
- It must contain `://`; the scheme is case-insensitive and must be `https` or
  `http`.
- The authority must contain a host.
- The authority must not contain `@`. Embedded credentials are rejected on
  every scheme, not only `http`.
- A bracketed IPv6 host must have a closing `]`, otherwise the endpoint is
  malformed.
- Plain `http` is accepted only for a loopback host. Every other host requires
  `https`.

The only hosts treated as loopback by this parser are `localhost`, any name
ending in `.localhost`, `127.0.0.1`, and `::1` (case-insensitive). That is a
narrower test than "any loopback address": for example,
`http://127.0.0.2:8000` is rejected because `127.0.0.2` is not one of those
names, even though the SSRF policy classifies it as loopback. Use `https` for
other addresses, or a local name such as `dev.localhost`.

Accepted examples:

```text
https://soroban-testnet.stellar.org
https://rpc.example.org:8443/rpc
http://localhost:8000
http://127.0.0.1:8000
http://dev.localhost:8000
https://[::1]:9000
```

Rejected examples:

| Endpoint | Reason |
| -------- | ------ |
| `http://example.com` | plain `http` is only allowed for loopback hosts |
| `ftp://example.com` | unsupported scheme; only `https` and `http` are accepted |
| `example.com` | missing scheme separator `://` |
| `https://user:pass@example.com` | embedded credentials |
| `https://` | missing host |
| `https://[::1` | malformed IPv6 host (no closing `]`) |

### Address policy (SSRF)

After parsing, the live transport checks the target address before each
connection. Loopback endpoints use `SsrfPolicy::local()`; every other endpoint
uses `SsrfPolicy::strict()`. Both policies allow public addresses. The local
policy additionally allows loopback; the strict policy does not. Every other
address class is blocked by both:

- private (RFC 1918: `10/8`, `172.16/12`, `192.168/16`);
- link-local, including the cloud metadata address `169.254.169.254`;
- IPv6 unique-local (`fc00::/7`) and IPv6 link-local (`fe80::/10`);
- shared (`100.64.0.0/10`), benchmarking (`198.18.0.0/15`), documentation,
  unspecified (`0.0.0.0`, `::`), multicast, broadcast, and reserved
  (`240.0.0.0/4`) ranges.

A literal IP is classified directly. A hostname is resolved with the endpoint's
effective port, and **every** returned address must pass; one blocked address
rejects the host. IPv4-mapped IPv6 addresses are classified as IPv4, so
`::ffff:127.0.0.1` is treated as loopback rather than as a public IPv6 address.
A host that cannot be resolved, or resolves to nothing, is rejected.

The policy is an outbound-request guard, not a sandbox. Resolution happens
during validation and the HTTP client then connects by hostname, so a DNS answer
that changes between the check and the connection is a residual TOCTOU risk.

### Trust model

- **Endpoints are not authenticated.** The tool does not verify that an endpoint
  is operated by Stellar, by a particular network, or by the party you expect.
  It only enforces the URL and address rules above. A `https` URL gets the TLS
  certificate check performed by the HTTP client, and that is the only
  identity signal.
- **RPC responses are untrusted input.** Responses are size-bounded before
  parsing, JSON is decoded without trusting its shape, and returned XDR is
  decoded with bounded readers and typed errors. A malformed, oversized, or
  hostile response produces an error, not executed code.
- **Fixtures are equally untrusted** when they come from an external source;
  the fixture transport only removes the network hop, not the need to trust the
  file's origin.
- **Loopback `http` is a development affordance.** It sends plaintext to a local
  process and cannot distinguish your own mock server from any other process on
  the machine. Do not treat a result obtained this way as evidence about a real
  network.
- **A successful lookup is not an endorsement.** Deployment inspection reports
  what the endpoint returned. It does not prove the endpoint was honest, that
  the contract is safe, or that the reported WASM hash matches a release you
  built.

`rpc.json` maps method names to results:

```json
{
  "getLedgerEntries": {
    "entries": [
      { "key": "AAAA...", "xdr": "AAAA...", "lastModifiedLedgerSeq": 123 }
    ]
  }
}
```

An error response is expressed as `{ "__error": { "code": -32000, "message": "..." } }`.

A method that is called several times can return results in order using
`{ "__sequence": [ result1, result2 ] }`. This is how interface verification
supplies the instance entry first and the code entry second.

## Deployed WASM retrieval

`deployment::deployed_wasm(client, wasm_hash_hex)` fetches the contract code
entry for a WASM hash and decodes the bytes. It builds a
`LedgerKey::ContractCode` key, calls `getLedgerEntries`, and decodes the
returned `LedgerEntryData`. It returns `None` when no code entry exists and
rejects hashes that are not 32 bytes. Decoded code larger than 64 MiB
(`MAX_WASM_BYTES`, the same bound used for local artifacts) is rejected with a
structured invalid-input error.

This enables interface comparison between a local artifact and the deployed
code (tracked as a follow-up).

## Ledger-entry cache

Repeated deployment lookups can reuse a small in-memory cache instead of issuing
a fresh `getLedgerEntries` call:

```rust
use observatory_deployment::{inspect_with_cache, deployed_wasm_with_cache, LedgerEntryCache};

let cache = LedgerEntryCache::with_default_capacity();
let info = inspect_with_cache(&client, contract_id, &cache)?;
let wasm = deployed_wasm_with_cache(&client, &hash, &cache)?;
```

The cache is **opt-in**: the existing `inspect` and `deployed_wasm` functions
keep their uncached behavior. Policy:

- Keyed by the base64-XDR ledger key for one process run.
- Bounded: `LedgerEntryCache::new(capacity)` retains at most `capacity` entries
  and evicts in insertion order. `with_default_capacity()` uses 128.
  A capacity of `0` disables caching.
- Negative results are cached too, so repeated lookups of a missing entry do not
  call the RPC again.
- Never persisted and never shared between runs, processes, or threads. Create a
  new cache per run and drop it when the run ends. `clear()` empties it.
- A cache hit returns the entry captured on the first call; it does not refresh
  ledger state. Use a fresh cache when a later lookup must observe new state.

`inspect_with_cache` and `deployed_wasm_with_cache` perform one transport call
for a repeated key. Unit tests assert this for both successful and missing
entries.

## Reported fields

`contract_id`, `wasm_hash`, `last_modified_ledger_seq`,
`live_until_ledger_seq`, `found`, and the bounded `storage` summary described
above (`null` when the instance has no storage map).

## Instance storage

The contract instance entry carries an optional `ScMap` of storage entries.
`inspect` decodes it and reports a bounded summary:

- `entry_count` — every entry the map declares;
- `inspected_entries` — how many entries contributed to the type counts;
- `truncated` — true when the map is larger than the inspection bound;
- `key_types` and `value_types` — counts of inspected keys and values by
  `ScVal` type name (for example `symbol`, `u32`, `address`).

Limits and safety:

- At most `MAX_STORAGE_ENTRIES_INSPECTED` (256) entries are inspected. A larger
  map still reports its true `entry_count` and sets `truncated`.
- Only type names and counts are serialized. Keys and values — including bytes,
  strings, and nested maps — are never included in the report.
- An instance without a storage map reports `storage: null`.
- No value is decoded recursively, so the work per entry is constant.

## Cross-network comparison

`deployment compare` compares one contract on two sides, independently reporting
whether the deployed WASM hashes match and whether the canonical interfaces
match. Each side is either a local artifact (`--left-wasm` / `--right-wasm`) or
an RPC fixture (`--left-fixture` / `--right-fixture`, which requires
`--contract`). Network labels default to `mainnet` and `testnet`.

```bash
stellar-contract-platform deployment compare \
  --contract C... \
  --left-fixture fixtures/mainnet.json --left-network mainnet \
  --right-fixture fixtures/testnet.json --right-network testnet
```

```bash
stellar-contract-platform deployment compare \
  --left-wasm contracts/token-v1.wasm --left-network v1 \
  --right-wasm contracts/token-v2.wasm --right-network v2 --json
```

The JSON report (`kind: deployment.compare`) contains `hash` and `interface`,
each `match`, `mismatch`, or `unknown` (when a side lacks the information), plus
the left and right metadata. When both interfaces are known, `interface_diff`
lists every change with its path, severity, and detail. The command always exits
`0`: the comparison is a report, not a policy verdict. No network access is
required when both sides are local artifacts or fixtures.

The library exposes the same pieces: `network_contract_from_wasm` for offline
inputs, `network_contract_from_rpc` for a fixture or live transport, and
`compare_networks`.

## Limitations

- Only WASM-backed instances expose a hash; Stellar-asset contracts report no
  hash.
- Caching is opt-in and in-memory only; see the cache policy above.
- A live provider means a network call; keep such use out of unit tests.

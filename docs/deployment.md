# Deployment inspection

`deployment inspect` looks up a deployed contract's instance entry and recovers
the executable WASM hash.

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

### Live HTTPS transport

`observatory_rpc::HttpTransport` implements `Transport` over HTTPS. It is behind
the `observatory-rpc` crate feature `live`, which is off by default:

```toml
observatory-rpc = { path = "crates/observatory-rpc", features = ["live"] }
```

`HttpTransport::new(endpoint)` rejects anything `Endpoint::parse` rejects
(`https` only, except loopback `http`), then applies the SSRF policy before every
request. Loopback endpoints use the local policy; all others must resolve to
public addresses. The transport never follows redirects, ignores environment
proxies, applies a 30-second request timeout, and caps a response body at 8 MiB;
`with_limits` overrides both limits. Failures are reported as typed RPC errors
that name the endpoint host, without echoing the URL or credentials.

The CLI does not switch to the live transport in this build; commands continue
to require a fixture. Wiring the transport into `deployment` and `verify` is
tracked separately.

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

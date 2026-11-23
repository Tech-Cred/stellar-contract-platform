# CLI reference

```
stellar-contract-platform [OPTIONS] <COMMAND>
```

## Global options

| Option | Description |
| ------ | ----------- |
| `--json` | Emit a machine-readable JSON report envelope. Equivalent to `--format json`; when both are given, `--json` wins. |
| `--format <human\|json>` | Output format; defaults to `human`. `text` is accepted as an alias for `human`. |
| `--config <FILE>` | Project configuration file; discovered automatically when omitted. |
| `--profile <NAME>` | Select a per-network configuration profile. See [configuration.md](configuration.md#per-network-profiles). |
| `-q`, `--quiet` | Suppress non-essential diagnostics (progress/notes and the `api serve` listening banner). Primary results still print, and `--quiet` wins over `--verbose`. |
| `-v`, `--verbose` | Emit diagnostics to stderr (repeatable). Diagnostics never go to stdout, so piped result output stays clean. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print version. |

## Commands

### `inspect <WASM> [--security] [--baseline <FILE>] [--dump-section <NAME>]`

Inspects a WASM artifact: size, version, artifact SHA-256, type/function/table/
global counts, memories, imports, exports, custom sections, and code size. With
`--security`, runs bounded heuristics.

`--baseline <FILE>` (requires `--security`) hides findings listed in a
suppression file and reports the count separately; see
[security.md](security.md#baseline-suppressions). The file may be JSON, YAML, or
TOML.

`--dump-section <NAME>` prints the named custom section payload as lowercase
hex. The dump is bounded at 64 KiB: a larger payload is rejected with an error
rather than truncated. An absent section is reported as absent and does not fail
the command. The section is only read; it is never executed.

### `spec <WASM> [--function <NAME>] [--type <TYPE>]`

Summarizes the contract specification. `--function` prints a single function;
`--type` prints a single user-defined type.

In human output, documentation strings carried by the specification are
rendered for functions and types, and for the type and per-field/case members
printed by `--type`. Documentation is omitted when empty; nothing is invented.
The `--json` output is unchanged.

### `events [<FILE>] [--rpc-fixture <FILE>] [--contract <ID>] [--topic <TEXT>] [--type <TYPE>] [--limit <N>] [--format csv]`

`--format csv` emits a deterministic fixed header:
`contract_id,ledger,tx_hash,event_type,topics,data`. The `topics` cell contains
a JSON array; commas, quotes, and line breaks are escaped according to CSV
rules. JSON and human-readable output are unchanged.

Decodes an event fixture and filters it. `--limit` is applied last.

`--rpc-fixture` instead reads a mock `getEvents` JSON-RPC fixture and paginates
it offline: provide a `{ "__sequence": [page1, page2, ...] }` fixture where each
page has `events`, and a `cursor` only when another page follows. Fetching is
opt-in and offline; there is no live network path in the unit test suite.

### `diff <OLD> <NEW>`

Diff two contract interfaces. Changes are classified as breaking,
non-breaking, or informational. Always exits `0`.

### `compat <OLD> <NEW> [--policy strict|lenient] [--policy-file <FILE>]`

Assess compatibility under a documented policy. Exits `6` when incompatible.
`--policy-file` loads explicit rules from a `.yml`, `.yaml`, `.toml`, or `.json`
document; see [compatibility.md](compatibility.md).

### `fingerprint <WASM>`

Prints the artifact SHA-256 and, when a specification is present, the canonical
interface fingerprint.

### `deployment inspect <CONTRACT_ID> --rpc-fixture <FILE> [--network <NET>] [--rpc-url <URL>]`

Inspects a deployed contract using a deterministic RPC fixture. The live HTTP
transport is not shipped yet; `--rpc-url` is validated and recorded only.

### `deployment compare --left-wasm <FILE> | --left-fixture <FILE> --right-wasm <FILE> | --right-fixture <FILE> [--contract <ID>] [--left-network <NET>] [--right-network <NET>]`

Compares one contract across two networks or local artifacts. The hash verdict
and interface verdict are reported separately: each is `match`, `mismatch`, or
`unknown`. When both interfaces are known, `interface_diff` carries per-change
detail. `--contract` is required only when a side uses an RPC fixture. Network
labels default to `mainnet` (left) and `testnet` (right). Always exits `0`. See
[deployment.md](deployment.md#cross-network-comparison).

### `verify artifact <WASM> --contract <ID> --rpc-fixture <FILE> [--network <NET>]`

Compares the local artifact hash against the deployed executable hash.

- `MATCH` exits `0`.
- `MISMATCH` exits `7`.
- `INSUFFICIENT_DATA` / `ERROR` exit `8`.

These are the defaults. `ci.fail_on` in the project configuration selects which
statuses fail; see [verification.md](verification.md#artifact-verification).

### `verify metadata <FILE>` and `verify compare <LEFT> <RIGHT>`

Parse and compare build metadata JSON documents.

### `repro <WASM> [--reference <WASM>]`

Reports `contractenvmetav0` and `contractmetav0` contents. With `--reference`,
also reports `match`/`mismatch` for the embedded metadata. The report always
states `source_reproduction: not_performed`; the tool never rebuilds from source
and never claims source reproducibility. See
[reproducibility.md](reproducibility.md).

With `--dependencies`, reports `dep:<name>` entries from `contractmetav0` and,
when a reference is supplied, a deterministic comparison of them. Missing
dependency data is reported as `unavailable`, never as an empty list. See
[reproducibility.md](reproducibility.md#dependency-metadata).

With `--sbom`, emits a minimal `observatory-sbom/1` document with the component
identity, SHA-256 artifact hash, and any `dep:` entries. Fields that cannot be
determined are `null` and listed in `unavailable`; the command does not invent
data. See [reproducibility.md](reproducibility.md#minimal-sbom).

### `doctor`

Prints capabilities, schema version, networks, and the RPC transport status.

### `completions <SHELL>`

Prints a completion script for `bash`, `zsh`, `fish`, or `powershell` to stdout.

```bash
# bash
stellar-contract-platform completions bash \
  > ~/.local/share/bash-completion/completions/stellar-contract-platform

# zsh (a directory on $fpath)
stellar-contract-platform completions zsh > "${fpath[1]}/_stellar-contract-platform"

# fish
stellar-contract-platform completions fish \
  > ~/.config/fish/completions/stellar-contract-platform.fish

# PowerShell (add the generated script to your profile, then restart the shell)
stellar-contract-platform completions powershell | Out-File -Encoding utf8 $PROFILE
```

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | success |
| `2` | usage error |
| `3` | input / filesystem error |
| `4` | parse / decode error |
| `5` | unsupported feature |
| `6` | incompatible interface change |
| `7` | verification mismatch |
| `8` | verification inconclusive |

## JSON envelope

Every `--json` report has the shape:

```json
{
  "schema_version": "1.0",
  "kind": "inspect",
  "tool": "stellar-contract-platform",
  "version": "0.1.0",
  "data": { }
}
```

Errors serialize as `{ "schema_version", "kind": "error", "code", "message" }`.

## Batch verification

`verify batch <MANIFEST>` verifies several artifacts against the same
fixture-backed RPC transport and exits with an aggregate status (`0` all match,
`7` any mismatch, `8` insufficient data). The manifest is JSON:

```json
{
  "entries": [
    {
      "artifact": "contracts/token.wasm",
      "contract": "C...",
      "rpc_fixture": "fixtures/rpc/token.json",
      "network": "testnet"
    },
    {
      "artifact": "contracts/vault.wasm",
      "contract": "C...",
      "rpc_fixture": "fixtures/rpc/vault.json"
    }
  ]
}
```

`network` is optional per entry and falls back to `--network`, then the project
configuration, then `testnet`. The JSON report (`kind: verify.batch`) contains
each result plus `summary.total`, `matched`, `mismatched`, and
`insufficient_data`. No artifact or repository file is written.

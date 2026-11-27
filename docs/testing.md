# Testing

## The local gate

Run the same checks as CI before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## Test layout

- Unit tests live next to the code in `#[cfg(test)]` modules.
- CLI integration tests live in `crates/observatory-cli/tests/cli.rs` and spawn
  the built binary against deterministic fixtures.
- Property tests live in `crates/observatory-interface/tests/canonicalization.rs`.
  They generate a bounded, fixed number of interfaces from the XDR fixture
  builders, check that declaration order does not change the fingerprint, and
  check that canonicalization is idempotent. Failures shrink to a minimal set
  of spec entries; there is no external randomness.
- `observatory-testutil` builds fixtures from bytes and real `stellar-xdr`
  values; no checked-in binary blobs are required so tests stay reviewable.
- API integration tests live in `crates/observatory-api/tests/`. The concurrency
  test starts an ephemeral loopback server and asserts exact rate-limit
  accounting under a fixed, bounded worker load.

## Golden report files

`crates/observatory-cli/tests/golden.rs` pins one JSON report per kind
(`inspect`, `spec`, `events`, `diff`, `compat`, `fingerprint`, `deployment`,
`verify`) against a checked-in file under
`crates/observatory-cli/tests/golden/`. Inputs are built deterministically at
test time. Before comparison the volatile envelope `version` is replaced with
`<version>`, and absolute paths or timestamps are replaced with `<path>` and
`<timestamp>` if they ever appear in a report. Everything else is compared
byte-for-byte, so a changed serialized field fails the suite.

After an intentional output change, regenerate the files and review the diff:

```bash
UPDATE_GOLDEN=1 cargo test -p observatory-cli --test golden
```

On PowerShell:

```powershell
$env:UPDATE_GOLDEN=1; cargo test -p observatory-cli --test golden
```

## Determinism rules

- Unit tests must not touch the network.
- Fixtures are built deterministically; tests assert exact values.
- RPC behaviour is exercised through `MockTransport` and fixture JSON.

## Fixtures

| Fixture | Built by |
| ------- | -------- |
| Minimal WASM module | `observatory_testutil::minimal_module` |
| Module with a custom section | `observatory_testutil::module_with_custom_section` |
| Module with a `name` section | `observatory_testutil::module_with_names` |
| Module with a `producers` section | `observatory_testutil::module_with_producers` |
| Module with a contract spec | `observatory_testutil::spec::*` + `module_with_spec` |
| Event fixtures | `observatory-events` test helpers (base64 `ScVal`) |
| Ledger entries | `stellar-xdr` `LedgerEntryData` encoded in tests |

## Benchmarks

Criterion benchmarks cover the performance-sensitive parsing and diffing paths:

| Benchmark | Crate | Measures |
| --------- | ----- | -------- |
| `wasm/inspect/2000_functions` | `observatory-wasm` | `observatory_wasm::inspect` on a generated 2000-function module |
| `spec/parse/3000_entries` | `observatory-spec` | `observatory_spec::parse` on 3000 generated spec entries |
| `interface/canonicalize/1500_entities` | `observatory-interface` | sorting a reversed `ContractInterface` |
| `interface/fingerprint/1500_entities` | `observatory-interface` | canonical JSON plus SHA-256 |
| `diff/1500_entities` | `observatory-diff` | `observatory_diff::diff` between two large interfaces |

Every input is built deterministically inside its bench file under
`crates/<crate>/benches/`; there are no checked-in fixtures and no randomness.
Each group uses a small sample size and a two-second measurement window so a
full run stays practical in CI. Run one crate at a time:

```bash
cargo bench -p observatory-wasm
cargo bench -p observatory-spec
cargo bench -p observatory-interface
cargo bench -p observatory-diff
```

`cargo bench` compiles in release mode by default. The numbers are
**machine-dependent**: they are useful for comparing runs on the same machine
and toolchain, not for comparing contributors or CI runners. The repository
does not enforce a timing threshold; record a baseline locally before and after
a change you suspect is a regression. Criterion writes its reports under
`target/criterion/`.

For a quick check that every bench target compiles and runs, use Criterion's
test mode:

```bash
cargo bench -p observatory-wasm -- --test
```

## Fuzzing

`fuzz/` is a separate `cargo-fuzz` crate and is deliberately **not** a workspace
member, so the stable workspace gate never needs nightly. Two targets run against
untrusted bytes:

- `spec_parse` feeds arbitrary bytes to `observatory_spec::parse`.
- `wasm_inspect` feeds arbitrary bytes to `observatory_wasm::inspect`. It never
  executes the module and performs no filesystem access.

Small valid seed corpora live in `fuzz/corpus/spec_parse/` and
`fuzz/corpus/wasm_inspect/`.

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
cargo fuzz run spec_parse
cargo fuzz run wasm_inspect
```

The scheduled `Fuzz smoke` workflow (daily at 03:41 UTC, plus manual dispatch)
builds and runs both targets on a pinned nightly (`nightly-2026-11-20`) and
`cargo-fuzz@0.13.2` for 60 seconds each. It writes a per-target job summary,
uploads any crashes under `fuzz/artifacts/<target>`, and fails the job whenever
a crash artifact is present, including when the smoke run itself already failed.

## Coverage

CI reports line coverage with [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov),
which uses LLVM's source-based instrumentation. The `Coverage` job runs on every
pull request and on pushes to `main`:

```bash
mkdir -p target/coverage
cargo llvm-cov --workspace --all-features \
  --lcov --output-path target/coverage/lcov.info
cargo llvm-cov report --summary-only | tee target/coverage/summary.txt
```

The job:

- writes a readable summary to the GitHub Actions job summary (visible from the
  pull request checks page),
- uploads `target/coverage/lcov.info` and `target/coverage/summary.txt` as the
  `coverage` artifact,
- runs an advisory coverage floor with `continue-on-error: true`. The floor is
  `0` while a baseline is established, so coverage is **reported but not
  enforced**. Raise `COVERAGE_ADVISORY_MIN_LINES` in `.github/workflows/ci.yml`
  once a sensible baseline is agreed.

Run the same commands locally after installing the tool:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
cargo llvm-cov --workspace --all-features --open
```

`cargo llvm-cov` merges the workspace test run, so the numbers include unit,
integration, and CLI tests. Doc tests are not instrumented. Failed tests still
fail the job; only the coverage floor is advisory.

## Adding tests

- Decoding changes must include malformed-input tests.
- New diff/compat rules must include a positive and a negative case.
- New CLI flags must include an integration test asserting exit code and output.

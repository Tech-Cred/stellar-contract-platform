# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Interface: `ContractInterface::event_fingerprint` provides a deterministic,
  order-independent SHA-256 fingerprint of declared events only, excluding
  functions, types, implementation details, and emitted event instances (#83).

- Events: `RpcClient::get_events` reads a bounded `getEvents` page, and
  `observatory-events` normalizes RPC events (`topic`/`value` ScVals) into
  `EventRecord`. `events --rpc-fixture` paginates a mock response offline (#36).
- RPC: the maximum response body size is configurable through
  `rpc.max_response_bytes` (default 8 MiB, zero rejected at load time) in
  addition to the existing live-transport bound (#119).

- Interface: `ContractInterface::is_subset_of` reports whether every function,
  type, and event in one interface structurally exists in another. The check
  compares canonical shapes, ignores documentation, is deterministic, and is
  explicitly structural rather than behavioral. See `docs/architecture.md`.
- Diff: `type_renamed` pairs one removed and one added struct, union, enum, or
  error enum only when their canonical shapes match exactly and the pairing is
  unambiguous. See `docs/interface-diff.md`.
- Diff: `event_renamed` pairs one removed and one added event only when their
  prefix topics, parameters, and data format match exactly and the pairing is
  unambiguous. See `docs/interface-diff.md`.
- Docs: `INTERFACE_SCHEMA_VERSION` policy covering additive versus breaking
  changes, consumer guidance, and the changelog requirement. See
  `docs/interface-schema-versioning.md`.
- Audit: the `audit` configuration block controls which rules run and their
  severity. `enabled` is an allow-list that defaults to every non-experimental
  rule, `severity` overrides `WARN`/`ERROR` per rule, and unknown rule ids are
  rejected. `inspect --security` honours the block. See `docs/security.md`.
- Configuration: per-network profiles under `profiles`, keyed by network name
  and selected with `--profile` or the `profile` field. A profile can override
  `rpc.endpoint` and `analysis.compatibility.policy`; malformed profile names,
  unknown selections, and invalid overrides are rejected at load time. See
  `docs/configuration.md`.
- WASM: `inspect` now reports bounded details for the start, data, element,
  and table sections: the start function index, segment counts and per-segment
  sizes or item counts, and table element/limit declarations. Data segment
  contents are never retained, and malformed detail sections still return a
  structured error. See `docs/contract-inspection.md` and
  `docs/schemas/inspect.schema.json`.
- SDK: `sdks/typescript`, a dependency-free ESM TypeScript client for the REST
  API. It covers every endpoint, sends `X-API-Key`, supports configurable
  timeouts and caller abort signals, maps stable API codes to typed errors, and
  ships `node:test` tests against a loopback mock plus an example. Models mirror
  the published JSON Schemas. See `sdks/typescript/README.md`.
- SDK: `observatory-client`, a typed blocking Rust client for the REST API. It
  reuses the engine's report types, supports `X-API-Key` authentication and
  configurable timeouts, maps stable API codes to a typed error enum, and
  round-trips every endpoint against a loopback API instance in its integration
  tests. See `docs/sdk.md`.
- CLI: `inspect --dump-section <NAME>` prints a named custom-section payload as
  bounded lowercase hex, capped at 64 KiB. Oversized payloads are rejected with
  a clear error, absent sections are reported as absent, and the section is
  never executed. See `docs/cli.md`.
- Fuzzing: a `wasm_inspect` `cargo-fuzz` target exercising
  `observatory_wasm::inspect` with a seed corpus. The scheduled workflow runs
  both fuzz targets and fails when a crash artifact is produced. See
  `docs/testing.md`.
- Audit: documented every heuristic rule id in `docs/security.md` with
  severity, rationale, limitations, and experimental status. A test checks the
  documented set against the crate's rule registry.
- Output: JSON Schema documents for every machine-readable report kind under
  `docs/schemas/`, versioned with `SCHEMA_VERSION`. Tests validate a
  representative report of each kind and reject invalid instances. See
  `docs/schemas/README.md`.
- Fuzzing: a `cargo-fuzz` crate with a `spec_parse` target fuzzing
  `observatory_spec::parse`, a valid seed corpus, and a scheduled nightly
  workflow that uploads crashes. `fuzz/` is not a workspace member, so the
  stable workspace gate does not need nightly. See `docs/testing.md`.
- RPC: `observatory_rpc::HttpTransport` implements the live HTTPS transport
  behind the off-by-default `live` feature. It revalidates the endpoint and SSRF
  policy before every request, does not follow redirects, ignores environment
  proxies, applies a 30-second timeout, and bounds responses to 8 MiB by
  default. See `docs/deployment.md`.
- Compatibility: `compat --policy-file <FILE>` loads explicit rule booleans from
  a `.yml`, `.yaml`, `.toml`, or `.json` document. Unknown fields, missing
  fields, and non-boolean values are rejected with the field named, the
  `--policy strict|lenient` presets keep working, and the JSON report echoes the
  resolved policy. See `docs/compatibility.md`.
- Diff: `function_renamed` pairs one removal with one addition only when their
  signatures match exactly and the pairing is unambiguous. Parameterless
  functions are never paired. See `docs/interface-diff.md`.
- Verification: `verify interface` reports the interface diff and strict
  compatibility verdict alongside `interface_match`, keeps artifact identity
  separate, and exposes an injectable `DeployedCodeSource`. Live fetching
  remains blocked on #14. See `docs/verification.md`.
- CLI: `repro <WASM> [--reference <WASM>]` reports `contractenvmetav0` and
  `contractmetav0` plus comparison state, and always states that source
  reproduction was not performed. See `docs/reproducibility.md`.
- Audit: duplicate interface entry rules (`interface.duplicate-*`,
  `type.duplicate-*`) and metadata/artifact consistency rules
  (`artifact.metadata-without-*`, `artifact.duplicate-metadata-section`). See
  `docs/security.md`.
- Events: accept raw base64 `ContractEvent` XDR, either as a bare input or an
  `xdr` field on a fixture entry, and normalize it to the existing `EventRecord`
  shape. See `docs/events.md`.
- Events: event types are canonicalized to lowercase, and diagnostic events are
  documented and tested as a distinct type that is filtered by contract, type,
  topic, and limit like any other event. See `docs/events.md`.
- CLI: `completions <shell>` generates bash, zsh, fish, and PowerShell completion
  scripts. See `docs/cli.md`.
- CI: reusable composite action at `.github/actions/observatory` that installs
  the CLI and runs `inspect`, `diff`, or `compat` with a JSON report. See
  `docs/ci.md`.

### Changed

- CLI: `verify artifact` and `verify interface` honour `ci.fail_on`, a
  comma-separated list of the verification statuses that fail the build. The
  default stays `MISMATCH,INSUFFICIENT_DATA,ERROR`; omitting a status makes it
  exit `0`, and `MATCH` is rejected. Previously the field was advisory. See
  `docs/verification.md` and `docs/ci.md`.
- Spec: decoding peeks at the 4-byte `ScSpecEntryKind` discriminant, so an
  unknown entry kind returns an `unsupported` error naming the kind, offset, and
  already-decoded entry count instead of a malformed-spec error. See
  `docs/contract-specifications.md`.
- CLI: an unsupported `--config` file extension is an unsupported-feature error
  (exit code `5`), not a usage error (`2`).

### Documentation

- API: documented the version lifecycle in `docs/API.md`, covering how versions
  are added, deprecated, and retired, notice expectations, and the separate roles
  of the API version and `schema_version`. No calendar dates are promised.

## [0.1.0] - 2026-10-28

First tagged release. Linux x86_64, macOS arm64, and Windows x86_64 archives
with SHA256 checksums are attached to the GitHub Release. crates.io publication
is still pending.

### Added

- CI: report test coverage with `cargo-llvm-cov` on pull requests. The job
  writes a summary to the workflow run, uploads an `lcov.info` artifact, and
  keeps the coverage floor advisory (`continue-on-error`). See `docs/testing.md`.
- Deployment: opt-in, bounded, per-run `LedgerEntryCache` with cached
  `inspect_with_cache` and `deployed_wasm_with_cache` lookups; repeated ledger
  keys reuse one `getLedgerEntries` call. See `docs/deployment.md`.
- Typed JSON-RPC error taxonomy: `RpcError`/`RpcErrorKind` classify standard
  JSON-RPC codes, preserve unknown raw codes, and expose `rpc_kind`/`rpc_code`
  in error reports. See `docs/rpc-errors.md`.
- Project configuration: `observatory.yml`/`.yaml`/`.toml`/`.json` with strict
  validation and auto-discovery, plus `--config`. Selects the compatibility
  policy and API auth/rate-limit defaults, and provides a default network for
  `verify`/`deployment`. See `docs/configuration.md`.
- Developer platform layer:
  - `observatory-platform`: application service layer plus API-key
    authentication (SHA-256 hashed secrets, never serialized), hierarchical
    RBAC, fixed-window rate limiting, and strict platform configuration.
  - `observatory-api`: versioned REST API at `/api/v1` with public
    health/readiness/version endpoints and six contract endpoints (inspect,
    spec, diff, compatibility, fingerprint, security), versioned report
    envelopes, request IDs, rate-limit headers, and a generated OpenAPI document
    that is kept in sync with the routes by a test.
  - CLI: `api serve` and `api openapi`.
- Workspace with 16 crates covering inspection, specification, interface model,
  events, diff, compatibility, RPC, deployment, verification, audit, output,
  platform, API, and the CLI.
- `observatory-wasm`: bounded, non-executing WASM inspection (sections, imports,
  exports, memories, custom sections, code size) and SHA-256 artifact hashing.
- `observatory-spec`: bounded `contractspecv0` parsing into a normalized,
  parser-independent model (functions, structs, unions, enums, error enums,
  events) with validation.
- `observatory-interface`: canonical interface model with deterministic
  interface fingerprinting and a known-value test vector.
- `observatory-events`: event fixture decoding, normalization, and filtering.
- `observatory-diff`: deterministic interface diff with breaking, non-breaking,
  and informational classification.
- `observatory-compat`: documented, configurable compatibility policy returning
  compatible / incompatible / unknown with reasons.
- `observatory-rpc`: transport abstraction, endpoint validation, typed
  `getLatestLedger` / `getNetwork` / `getLedgerEntries` models, and a
  deterministic mock/fixture transport.
- `observatory-deployment`: deployed contract inspection and `ContractExecutable`
  WASM hash recovery from real ledger-entry XDR.
- `observatory-verify`: local-vs-deployed verification and `contractmetav0` /
  `contractenvmetav0` build metadata parsing and comparison.
- `observatory-audit`: bounded, deterministic interface/artifact heuristics with
  clearly labelled experimental rules.
- `observatory-output`: versioned JSON report envelopes and stable error reports.
- `observatory-cli`: `inspect`, `spec`, `events`, `diff`, `compat`,
  `fingerprint`, `deployment`, `verify`, and `doctor`, all with `--json`.
- CI: format, clippy, and tests on Linux, Windows, and macOS.
- Release: tag-driven Linux/macOS/Windows binaries with SHA256 checksums.
- Documentation: `docs/WHY_OBSERVATORY.md`, `docs/APPEAL.md`, and an offline
  `demo/` with deterministic old/new WASM fixtures.

### Changed

- Build: raised the workspace MSRV from 1.85 to 1.88 so the locked dependency set
  (`wasmparser` 0.259, `stellar-strkey` 0.0.18, `serde_with` 3.23) resolves and
  the MSRV CI job matches the workspace `rust-version`.
- The repository was renamed to `stellar-contract-platform`. The CLI binary
  (`stellar-contract-platform`), the `observatory-*` crates, and the product
  name remain unchanged; only the repository URL and clone instructions changed.
- Documentation: repository, installation, and Wave links now use
  `AyinkxLab/stellar-contract-platform`.

### Security

- Replaced the unsound, unmaintained `serde_yml` parser (which pulled in
  `noyalib` 0.0.5, RUSTSEC-2026-0333) with the maintained `serde_yaml_ng`
  fork. YAML project configuration parsing is unchanged.

### Documentation

- Installation: document the prebuilt archives and the working
  `cargo install --git` path (package `observatory-cli`, binary
  `stellar-contract-platform`). See `docs/installation.md`.
- Project status, final audit, issue backlog, and Wave board now match `main`.

### Notes

- No live HTTP RPC transport is shipped yet. Deployment and verification run
  against deterministic RPC fixtures.
- The audit crate is not a security auditor.

# Report schemas

These [JSON Schema](https://json-schema.org/draft/2020-12/) documents describe
the machine-readable reports emitted by the CLI and REST API. There is one
document per report kind, named `<kind>.schema.json`.

Every report is wrapped in the envelope described by
[`Report`](../../crates/observatory-output/src/lib.rs): `schema_version`,
`kind`, `tool`, `version`, and `data`. The `schema_version` const in each
document is the envelope version from `observatory_core::SCHEMA_VERSION`; the
`kind` const names the report. A schema changes when the envelope version
changes, and `crates/observatory-output` tests assert both stay in sync.

`error.schema.json` describes error reports, which use `code` and `message`
instead of `data`.

## Canonical interface

`interface.schema.json` describes the canonical `ContractInterface` document
produced by `observatory_interface::ContractInterface::canonical_json()`. Its
`schema_version` const is `observatory_interface::INTERFACE_SCHEMA_VERSION`; the
tests in `crates/observatory-interface` assert the two stay in sync and reject a
mismatched version. The `diff` CLI accepts these documents as either side of a
comparison; see [`interface-diff.md`](../interface-diff.md).

## Validation

The tests in `crates/observatory-output/src/lib.rs` validate a representative
instance of each kind and assert that invalid instances are rejected.

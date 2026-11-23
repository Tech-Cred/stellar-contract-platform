# Fingerprinting

Fingerprints provide stable identity for artifacts and interfaces.

## What each fingerprint covers

| Fingerprint | Covers | Does not cover |
| ----------- | ------ | -------------- |
| Artifact SHA-256 | The exact WASM bytes | Interface meaning, source |
| Interface SHA-256 | The canonical interface (functions, types, events) | Implementation, metadata |
| Event-interface SHA-256 | Canonical declared events | Functions, types, emitted event instances, implementation |

## Artifact fingerprint

`fingerprint <wasm>` prints the SHA-256 of the artifact bytes. This is the same
value used by `verify artifact`.

The CLI streams the file through a bounded buffer
(`observatory_wasm::artifact_fingerprint_file`) instead of loading it whole, so
peak memory stays constant regardless of artifact size. The digest is identical
to hashing the full contents at once. The interface fingerprint still needs the
artifact in memory; when an artifact exceeds the load bound it is omitted while
the artifact fingerprint is still reported.

## Interface fingerprint

When a `contractspecv0` section is present, the canonical interface is serialized
to deterministic JSON and hashed. Canonicalization sorts name-keyed collections
and preserves sequence-keyed collections, so:

- reordering function declarations does **not** change the fingerprint,
- reordering function parameters **does** change the fingerprint,
- changing a type does change the fingerprint.

Known-value test vectors pin the digest of representative interfaces to detect
accidental format changes. The vectors in
`crates/observatory-interface/src/lib.rs` cover primitives, composite types,
user-defined types, events, and a large interface.

The vectors pin the **canonical serialization format, not interface semantics**.
They exist to catch an accidental change to the canonical JSON encoding (field
names, field order, type tags). Changing a digest therefore requires a
deliberate decision that the wire format has changed; it must never be updated
merely to make a test pass.

## Event-interface fingerprint

`ContractInterface::event_fingerprint` hashes the interface schema version and
the canonical list of declared contract events. Event declarations are sorted
by name, while the order of each event's prefix topics and parameters remains
semantic. Non-event declarations do not affect this fingerprint.

This fingerprint describes the events a contract declares in its specification.
It does not include, inspect, or attest to event instances emitted at runtime.

## Warning

```
same interface  !=  same implementation
```

Two contracts can expose an identical interface and behave differently. The
interface fingerprint captures the interface, not the behavior.

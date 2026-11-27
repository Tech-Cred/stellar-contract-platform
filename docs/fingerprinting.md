# Fingerprinting

Fingerprints provide stable identity for artifacts and interfaces.

## What each fingerprint covers

| Fingerprint | Covers | Does not cover |
| ----------- | ------ | -------------- |
| Artifact digest | The exact WASM bytes | Interface meaning, source |
| Interface digest | The canonical interface (functions, types, events) | Implementation, metadata |

Both digests use SHA-256 by default. `--algorithm sha512` selects SHA-512. The
report always includes an `algorithm` field so a digest can never be mistaken
for another algorithm.

## Artifact fingerprint

`fingerprint <wasm>` prints the SHA-256 of the artifact bytes by default. This
is the same value used by `verify artifact`.

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

Changing the algorithm changes the digest but not the canonical bytes, so
existing SHA-256 fingerprints remain valid. Known-value test vectors pin the
digest of representative interfaces for every supported algorithm to detect
accidental format changes. The vectors in
`crates/observatory-interface/src/lib.rs` cover primitives, composite types,
user-defined types, events, and a large interface.

The vectors pin the **canonical serialization format, not interface semantics**.
They exist to catch an accidental change to the canonical JSON encoding (field
names, field order, type tags). Changing a digest therefore requires a
deliberate decision that the wire format has changed; it must never be updated
merely to make a test pass.

## Warning

```
same interface  !=  same implementation
```

Two contracts can expose an identical interface and behave differently. The
interface fingerprint captures the interface, not the behavior.

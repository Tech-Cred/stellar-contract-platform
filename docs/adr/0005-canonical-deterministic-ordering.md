# ADR 0005: Canonical Ordering and Versioned Machine-Readable Envelopes

- **Status:** Accepted
- **Deciders:** Observatory Maintainers

## Context

CI pipelines, security gates, and downstream tooling compare Observatory outputs
across builds and commits. If map iteration order, compiler section ordering, or
unversioned JSON payloads vary between runs, automated diffs and interface
fingerprints become unstable.

## Decision

1. **Canonical Ordering (`observatory-spec`, `observatory-interface`, `observatory-diff`):**
   Sort all name-keyed collections (functions, structs, unions, enums, error
   enums, events, and diff entries) deterministically, while preserving declared
   positional order for sequence-keyed items where order is semantically
   meaningful (function parameters, struct fields, union/enum cases).
2. **Versioned Report Envelopes (`observatory-output`, `observatory-api`):**
   Wrap every JSON output in a stable envelope carrying `schema_version`, `kind`,
   `tool`, `version`, and `data`.

## Consequences

### Positive
- Identical contract interfaces always produce byte-for-byte identical JSON
  reports and `interface_fingerprint` hashes across operating systems and
  compiler runs.
- Downstream CI consumers can pin `schema_version` and validate report `kind`
  mechanically.

### Negative / Trade-offs
- Any breaking change to report fields requires bumping `schema_version` and
  maintaining explicit synchronization tests.

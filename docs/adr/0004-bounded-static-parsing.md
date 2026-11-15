# ADR 0004: Enforce Strict Resource Bounds on Static Artifact and HTTP Parsing

- **Status:** Accepted
- **Deciders:** Observatory Maintainers

## Context

Malformed or adversarial `.wasm` binaries, oversized XDR custom sections, or
large HTTP request bodies can exhaust memory or CPU during parsing even without
code execution.

## Decision

Enforce explicit compile-time and runtime resource ceilings across all entry
points:
- Bound maximum WASM artifact size (`MAX_WASM_BYTES` in `observatory-core`),
  custom section sizes, and XDR decoding limits before allocating buffers.
- Bound HTTP request payload sizes (`MAX_BODY_BYTES`), header counts, and read
  buffers in `observatory-api::http`.
- Reject trailing bytes or truncated XDR streams deterministically with typed
  error codes rather than panicking.

## Consequences

### Positive
- Predictable memory footprint and resilience against decompression bombs or
  oversized payloads in both CLI and API modes.
- Clear `413 Payload Too Large` and `400 Bad Request` responses on boundary
  violations.

### Negative / Trade-offs
- Extremely large non-standard WASM artifacts exceeding `MAX_WASM_BYTES` are
  rejected upfront.

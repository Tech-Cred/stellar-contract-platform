# ADR 0001: Never Execute Untrusted Contract WASM

- **Status:** Accepted
- **Deciders:** Observatory Maintainers

## Context

The Observatory inspects arbitrary `.wasm` smart contract artifacts supplied via
CLI arguments or HTTP API payloads (`POST /api/v1/contracts/*`). Executing
untrusted WebAssembly modules—even inside a sandboxed host runtime—introduces
execution-time resource exhaustion risks, host-environment coupling, and
nondeterministic side effects.

## Decision

The Observatory **never instantiates or executes WebAssembly bytecode**. All
contract intelligence (`observatory-wasm`, `observatory-spec`,
`observatory-interface`, `observatory-audit`, `observatory-verify`) is performed
strictly through static analysis using a streaming parser (`wasmparser`) and XDR
custom-section decoders (`stellar-xdr`).

## Consequences

### Positive
- Zero risk of untrusted code execution on CLI workstations, CI runners, or API
  servers.
- Fast, deterministic inspection that does not require instantiating a Soroban
  host environment or ledger snapshot.

### Negative / Trade-offs
- Dynamic runtime behavior (such as storage mutations dependent on runtime inputs)
  cannot be observed from the WASM artifact alone; security findings in
  `observatory-audit` are explicitly scoped as static structural heuristics.

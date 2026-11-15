# ADR 0003: Offline-First, Fixture-Driven RPC Transport Abstraction

- **Status:** Accepted
- **Deciders:** Observatory Maintainers

## Context

Contract deployment inspection (`observatory-deployment`) and artifact
verification (`observatory-verify`) query Soroban JSON-RPC state (`getLedgerEntries`,
network metadata, and contract instances). Relying on live public RPC endpoints
in unit tests or default CI pipelines causes flaky builds, rate-limiting
failures, and SSRF exposure when running as an API service.

## Decision

Define a synchronous, transport-agnostic `RpcTransport` trait in
`observatory-rpc` with typed request/response models and a deterministic
fixture/mock transport (`FixtureTransport`). All unit and integration tests run
100% offline against checked-in or generated XDR fixtures (`observatory-testutil`).

## Consequences

### Positive
- Every `cargo test` run is fast, reproducible, and completely independent of
  external network availability.
- The bundled REST API (`observatory-api`) performs zero outbound network
  requests by default, structurally eliminating SSRF vectors until a hardened
  live transport is explicitly enabled.

### Negative / Trade-offs
- Live Soroban RPC queries require an explicit transport adapter implementation
  or pre-fetched RPC fixture file (`--rpc-fixture`).

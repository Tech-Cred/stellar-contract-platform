# ADR 0002: Separate Interface Diff Description from Compatibility Judgement

- **Status:** Accepted
- **Deciders:** Observatory Maintainers

## Context

When comparing two versions of a Soroban contract interface, different consumers
and release pipelines apply different upgrade policies. Treating diffing and
compatibility assessment as a single boolean check conflates objective structural
facts with policy decisions.

## Decision

Split interface comparison into two distinct crates and layers:
1. **`observatory-diff` (Description):** Enumerates *what changed* between two
   `ContractInterface` models (`FunctionAdded`, `FunctionRemoved`,
   `FunctionChanged`, `FunctionRenamed`, `TypeAdded`, `TypeRemoved`,
   `TypeChanged`, `EventAdded`, `EventRemoved`, `EventChanged`) and assigns a
   default structural severity without claiming an overall compatibility verdict.
2. **`observatory-compat` (Judgement):** Evaluates an `InterfaceDiff` against an
   explicit policy (`CompatibilityPolicy::Strict` or `Lenient`) to produce a
   structured `CompatibilityAssessment` and CLI exit code (`6` on incompatible
   changes).

## Consequences

### Positive
- Callers can inspect raw structural diffs without being forced into a single
  upgrade policy.
- New compatibility policies can be added in `observatory-compat` without
  modifying the diff engine in `observatory-diff`.

### Negative / Trade-offs
- Maintaining two crates (`observatory-diff` and `observatory-compat`) requires
  keeping change classifications aligned across both layers.

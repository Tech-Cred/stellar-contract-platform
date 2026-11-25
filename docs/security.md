# Security

## Model

Stellar Contract Observatory treats every artifact, specification, event, and RPC
response as untrusted input. The core guarantees:

- **No execution.** WASM is never run. Inspection is static and streaming.
- **Bounded parsing.** Input sizes and entry counts are limited; failures return
  structured errors, never panics on malformed input.
- **No network by default.** Unit tests and core workflows are offline.
- **Structured errors.** Errors carry stable machine-readable codes.

## Heuristics

`inspect --security` runs bounded, deterministic checks from `observatory-audit`:

- specification validation (duplicates, unknown references, arity),
- empty/duplicate names,
- events with more than two prefix topics,
- artifact checks (no code section, no `contractspecv0`, truncated listings,
  oversized specification sections).

### Rules

Every emitted id is listed here. `docs/security.md` and the rule registry in
`observatory-audit` are checked against each other by a test.

| Id | Severity | Experimental | Rationale | Limitations |
| -- | -------- | ------------ | --------- | ----------- |
| `spec.error` | ERROR | no | Specification validation found an inconsistency: a duplicate function or type name, a reference to an unknown type, or more than one return type. | Mirrors `observatory_spec::validate`; it proves internal consistency only, not that the spec matches deployed behaviour. |
| `spec.warning` | WARN | no | Specification validation found a warning, currently a duplicate event name. | Event payload shape is not validated. |
| `spec.info` | WARN | no | Reserved for an informational specification issue. | No current check emits it. |
| `interface.empty` | WARN | yes | The interface declares no functions, types, or events, so there is nothing to inspect or call. | A stub or intermediate build artifact can legitimately be empty. |
| `interface.no-functions` | WARN | yes | The interface declares types or events but no functions, so consumers have no entry point. | Event-only or type-only ABI surfaces are possible, although unusual. |
| `naming.mixed-script` | WARN | yes | A name mixes ASCII and non-ASCII letters, which can be used to create visually confusable (homoglyph) identifiers. | Experimental and low confidence. Identifiers from non-Latin languages legitimately mix scripts; review each finding in context. This is not a vulnerability. |
| `naming.zero-width` | WARN | yes | A name contains zero-width, control, or bidirectional formatting characters that are invisible in many editors and can disguise an identifier. | Experimental and low confidence. Some generated bindings may include unusual characters legitimately. This is not a vulnerability. |
| `interface.duplicate-function` | ERROR | no | Two functions with one name cannot both be called unambiguously. | Compares names only; an overload with a distinct name is not reported. |
| `interface.duplicate-type` | ERROR | no | A user-defined type name must resolve to a single definition. | Applies to structs, unions, enums, and error enums across the whole interface. |
| `interface.duplicate-event` | ERROR | no | Two events with one name cannot be told apart by consumers. | Compares names only, not topics or payloads. |
| `function.empty-name` | ERROR | no | A function with a blank name cannot be exported or called by name. | Checks the name after trimming whitespace. |
| `function.duplicate-param` | WARN | yes | Duplicate parameter names confuse generated clients and documentation even though the ABI is positional. | Compares exact, non-empty names within one function. |
| `function.unknown-type` | ERROR | no | A parameter references a user-defined type with no definition, so the call ABI cannot be resolved. | Checks parameter types only; return and event types are covered by `spec.error`. |
| `event.too-many-prefix-topics` | ERROR | no | A Soroban event may declare at most two prefix topics; more cannot be emitted by a conforming contract. | Static declaration check; runtime topic counts are never observed. |
| `type.duplicate-field` | WARN | yes | A struct with duplicate field names is almost certainly a code-generation bug, although the XDR encoding remains decodable. | Compares names only, not field types or order. |
| `type.duplicate-case` | WARN | yes | Duplicate union or enum case names break name-based matching, even though numeric encodings may still be distinct. | Compares names only, not the numeric values. |
| `artifact.no-code` | WARN | no | A module with no code section has nothing to deploy or execute. | Does not detect a present but empty code section. |
| `artifact.no-contract-spec` | WARN | yes | A module with no `contractspecv0` section has no embedded interface and may not be a Soroban contract. | A contract can be valid with its ABI distributed separately from the artifact. |
| `artifact.truncated-report` | WARN | no | The import, export, or custom-section listing hit a parser bound, so the report is incomplete. | Reports that truncation happened, not what was omitted. |
| `artifact.no-memory` | WARN | yes | Soroban contracts normally declare linear memory, so its absence is suspicious. | Some valid modules do not declare memory that this static listing observes. |
| `artifact.memory64` | WARN | yes | A 64-bit linear memory (`memory64` proposal) is unexpected for a Soroban contract, which targets 32-bit linear memory. | Reports the declared flag only; it does not judge whether a non-Soroban module is otherwise valid. |
| `artifact.oversized-spec` | WARN | yes | A `contractspecv0` section larger than 4 MiB is unusual and may indicate generated or padded data. | The 4 MiB threshold is heuristic; large generated interfaces can exceed it legitimately. |
| `artifact.metadata-without-contract-spec` | WARN | yes | Soroban metadata with no `contractspecv0` section means the embedded build metadata does not describe an inspectable interface. | Some toolchains may emit metadata before the spec. |
| `artifact.metadata-without-code` | WARN | yes | Metadata claims a Soroban build but the module has no code section, so the artifact cannot be the built contract. | Metadata-only artifacts are reported even when intentionally produced. |
| `artifact.duplicate-metadata-section` | WARN | yes | More than one `contractmetav0`/`contractenvmetav0` section makes the effective metadata parser-dependent. | Reports each duplicated section name once; it does not compare section contents. |

All rules read only the in-memory interface or `WasmReport`, use bounded
iteration over already-parsed collections, and are deterministic. Duplicate
checks report each duplicated name once.

Rules marked `experimental` may change. Heuristic ids are stable for CI.

### Finding JSON

Every finding in the security report carries the same bounded shape:

```json
{
  "id": "artifact.no-code",
  "severity": "WARN",
  "message": "Potential issue: module contains no code section",
  "path": null,
  "experimental": false,
  "confidence": "HIGH",
  "evidence": ["module contains no code section"],
  "recommendation": "Include a code section or verify this is the intended artifact."
}
```

- `message` always begins with `Potential issue:`. Findings describe observations
  and never claim a confirmed vulnerability.
- `confidence` is `HIGH`, `MEDIUM`, or `LOW`. It reflects how directly the
  heuristic result follows from the parsed input, not a security verdict.
- `evidence` has one or two strings: the observation and, when available, the
  stable path where it was seen. The list is bounded to keep reports readable.
- `recommendation` is a non-prescriptive review step. It does not guarantee that
  a change is required.

The full machine-readable contract is
[`docs/schemas/security.schema.json`](schemas/security.schema.json). SARIF output
includes the same three fields in each result's `properties` object.

### Configuration

`inspect --security` reads the `audit` block from the project configuration:

```yaml
audit:
  enabled:              # default: every non-experimental rule
    - spec.error
    - artifact.no-code
  severity:
    artifact.no-code: ERROR
```

- `enabled` is an allow-list. A rule not listed is skipped. When the field is
  absent, all non-experimental rules run and experimental rules are skipped;
  list an experimental rule by id to opt in.
- `severity` replaces a rule's default severity (`WARN` or `ERROR`) after the
  rule runs. Overriding `WARN` to `ERROR` can change the overall audit status.
- Every id must appear in the rule table and in the crate's `RULE_IDS` registry.
  An unknown id is a configuration error, not a silently ignored rule.

### Baseline suppressions

Accepted findings can be hidden with `inspect --security --baseline <FILE>`
(`.json`, `.yml`/`.yaml`, or `.toml`). Suppressed findings are removed from the
report but counted in `suppressed`, and the status is recomputed from the
remaining findings, so the result never pretends a finding was fixed.

```yaml
suppressions:
  - rule: artifact.no-code
    reason: Intermediate build artifact; the deployable module is checked in CI.
    expires: 2026-12-31
  - rule: function.empty-name
    path: function::
    reason: Generated stub retained for ABI compatibility.
```

- `rule` must be a registered rule id.
- `path` is optional. When present it must match the finding's path exactly;
  when absent the rule is suppressed at every path.
- `reason` is required and must be non-empty, so CI history records why the
  waiver exists.
- `expires` is optional and is the last day the suppression applies, in
  `YYYY-MM-DD`. After that date the finding is reported again; expired entries
  are not errors, so stale baselines surface instead of disappearing.
- Unknown fields, unknown rule ids, empty paths or reasons, and malformed dates
  are errors (exit code `2`), never ignored.
- The file is validated even when no finding matches.

> These checks are **not** a security audit and provide no guarantees. They catch
> structural inconsistencies, nothing more.

## SSRF policy

The RPC layer ships an address policy (`observatory_rpc::net`) that must be
applied before any live request. It classifies literal addresses and resolves
hostnames, then rejects any non-public result:

- loopback, private (RFC 1918), link-local, and cloud metadata
  (`169.254.169.254`);
- IPv6 unique-local and link-local;
- shared (`100.64.0.0/10`), benchmarking, documentation, unspecified, multicast,
  broadcast, and reserved ranges;
- IPv4-mapped IPv6 addresses are classified as IPv4, so `::ffff:127.0.0.1` is
  rejected.

`SsrfPolicy::strict()` blocks loopback; `SsrfPolicy::local()` permits it for
local development only. Endpoints can be checked with
`Endpoint::validate_ssrf(&policy)`. The live transport calls this before every
request.

The fixture transport performs no network I/O, so SSRF is structurally absent
on that path. The live transport (`observatory-rpc` feature `live`) revalidates
the endpoint and address policy before each connection, does not follow
redirects, does not use environment proxies, and bounds the response body.

The URL rules, accepted and rejected examples, and the endpoint trust model
(including that RPC responses are untrusted input) are documented in
[deployment.md](deployment.md#endpoint-validation-and-trust).

## SARIF output

`inspect --security --format sarif` renders the same findings as a
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
document for code-scanning dashboards:

- `tool.driver` names the tool and lists one rule per emitted finding id, each
  with a short description and a `defaultConfiguration.level` mapped from the
  audit severity (`ERROR` to `error`, `WARN` to `warning`).
- `results` carry `ruleId`, `level`, `message.text`, and a `locations` entry
  with the finding path when one is recorded.
- Rules and results are sorted, so the same report produces the same document.

The document is not a report envelope, so there is no `docs/schemas` JSON
Schema for it; the structural test in `observatory-audit` validates the SARIF
shape instead. Like the findings themselves, it describes structural
inconsistencies and is **not** a security certification.

## What is out of scope

- Detecting malicious contract logic.
- Validating that a deployed contract is safe.
- Trusting or authenticating RPC endpoints (live request authentication is not
  implemented).

## Reporting

See [SECURITY.md](../SECURITY.md).

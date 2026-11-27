# Compatibility

`compat` applies an explicit policy to the interface diff and returns a verdict
with reasons. It is intentionally not a boolean.

## Statuses

- `compatible` — no breaking change under the active policy.
- `incompatible` — at least one breaking change under the active policy.
- `unknown` — there is not enough information to decide. In particular, when the
  baseline interface is empty there is no public surface to compare, so the
  result is `unknown` rather than `compatible`.

## Policy rules

| Rule | Strict (default) | Lenient |
| ---- | ---------------- | ------- |
| Removing a function | incompatible | note |
| Changing a function signature | incompatible | note |
| Removing a type | incompatible | note |
| Renaming a type (identical shape) | incompatible | note |
| Changing a type definition | incompatible | note |
| Adding an enum case | incompatible (default) | note |
| Removing an event | incompatible | note |
| Renaming an event (identical shape) | incompatible | note |
| Changing an event | incompatible | note |
| Adding a function, type, or event | compatible | compatible |
| Documentation-only change | compatible | compatible |

Relaxing a rule does **not** hide the change: it is reported as a non-breaking
note with its path and explanation.

### Enum case additions

`enum_case_addition_is_breaking` governs only the addition of a case to an
existing enum or error enum. It defaults to `true` (breaking under `strict`) and
is `false` under `lenient`. The default is deliberate: adding a variant can break
consumers with exhaustive matches, fixed discriminants, or stored numeric values.
Teams that treat enums as open can set the flag to `false`. The flag does not
affect struct or union changes, enum case removals, value changes, type renames,
or any function/event rule; `type_change_is_breaking` still covers those other
type changes.

The diff reports an addition as `enum_case_added` only when every existing case
keeps its name, value, and relative order. Otherwise the change stays
`type_changed` and follows `type_change_is_breaking`.

## Policy document

`--policy-file <FILE>` loads the rules from a document instead of a preset. The
format follows the configuration conventions and is inferred from the extension:
`.yml`, `.yaml`, `.toml`, or `.json`. Every rule is required, and unknown fields
are rejected:

```yaml
function_removal_is_breaking: true
signature_change_is_breaking: true
type_removal_is_breaking: true
type_change_is_breaking: true
enum_case_addition_is_breaking: true
event_removal_is_breaking: true
event_change_is_breaking: true
```

The same document in TOML:

```toml
function_removal_is_breaking = false
signature_change_is_breaking = false
type_removal_is_breaking = false
type_change_is_breaking = false
enum_case_addition_is_breaking = false
event_removal_is_breaking = false
event_change_is_breaking = false
```

A document that sets every rule to `true` is equivalent to
`--policy strict`; setting every rule to `false` is equivalent to
`--policy lenient`. The presets keep working. `--policy` and `--policy-file`
cannot be used together.

An unknown field, a missing field, or a non-boolean value is an invalid-policy
error (exit code `2`) whose message names the field. The JSON report echoes the
resolved rules in its `policy` object, so a reviewer can see exactly what was
applied.

## Why a policy

Compatibility depends on consumers. A removed event may break an indexer while
being irrelevant to a caller that only invokes functions. The policy makes the
assumption explicit and reviewable rather than baking it into the tool.

## JSON output

```json
{
  "status": "incompatible",
  "policy": { "signature_change_is_breaking": true, ... },
  "reasons": [
    { "breaking": true, "path": "function::transfer", "message": "..." }
  ],
  "diff": { "changes": [], "summary": { } }
}
```

## Exit codes

`compat` exits `6` on `incompatible` and `0` otherwise, so CI can gate merges.

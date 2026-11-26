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

| Rule | Strict (default) | Additive-only | Lenient |
| ---- | ---------------- | ------------- | ------- |
| Removing a function | incompatible | incompatible | note |
| Changing a function signature | incompatible | incompatible | note |
| Removing a type | incompatible | incompatible | note |
| Renaming a type (identical shape) | incompatible | incompatible | note |
| Changing a type definition | incompatible | incompatible | note |
| Removing an event | incompatible | incompatible | note |
| Renaming an event (identical shape) | incompatible | incompatible | note |
| Changing an event | incompatible | incompatible | note |
| Adding a function, type, or event | compatible | compatible | compatible |
| Documentation-only change | compatible | compatible | compatible |

`--policy additive-only` (also accepted as `additive_only`) states the
additive-evolution contract explicitly: callers may add functions, types, or
events without a version bump, but may not remove, rename, or modify any
existing surface. Its rule values match `strict` today; the named preset makes
that guarantee reviewable instead of leaving it to be inferred from six
booleans. An empty baseline still yields `unknown`, because there is no existing
surface to add to.

Relaxing a rule does **not** hide the change: it is reported as a non-breaking
note with its path and explanation.

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
event_removal_is_breaking: true
event_change_is_breaking: true
```

The same document in TOML:

```toml
function_removal_is_breaking = false
signature_change_is_breaking = false
type_removal_is_breaking = false
type_change_is_breaking = false
event_removal_is_breaking = false
event_change_is_breaking = false
```

A document that sets every rule to `true` is equivalent to both
`--policy strict` and `--policy additive-only`; setting every rule to `false`
is equivalent to `--policy lenient`. The presets keep working. `--policy` and
`--policy-file` cannot be used together.

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

# Interface compatibility fixtures

These WASM modules are small, committed artifacts used by the
`.github/workflows/compat.yml` job. They carry only a `contractspecv0` custom
section, so the compatibility check runs without a Soroban or Rust-to-WASM
toolchain.

They are assembled from the same XDR spec entries that
`observatory-testutil::module_with_spec` builds in tests; they are not deployed
contracts.

| Pair | Baseline | Head | Expected |
| ---- | -------- | ---- | -------- |
| Gate | `baseline.wasm` | `head.wasm` | compatible (`total_supply` added) |
| Negative | `negative/baseline.wasm` | `negative/head.wasm` | incompatible (`transfer` removed) |
| Enum additions | `enum-addition/baseline.wasm` | `enum-addition/head.wasm` | incompatible by default; compatible with `enum-addition/policy.json` |

The gate pair is what a pull request compares: editing `head.wasm` to remove or
change a public entry makes the workflow fail with exit code `6`. The negative
pair exists so the workflow also proves its own failure path on every run.

The enum-addition pair adds one case to both an enum and an error enum while
leaving all existing cases and function signatures unchanged. The committed
policy document keeps type changes breaking but opts out of the enum-addition
rule, proving the flag is isolated. The CLI integration suite exercises both
verdicts against these files.

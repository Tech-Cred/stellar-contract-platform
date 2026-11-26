# Contract inspection

`inspect` answers "what is inside this artifact?" without executing it.

## Reported fields

| Field | Meaning |
| ----- | ------- |
| `size_bytes` | Artifact size. |
| `version` | WASM binary version. |
| `artifact_sha256` | SHA-256 of the artifact bytes; the artifact identity. |
| `type_count` | Number of declared types. |
| `function_count` | Number of declared functions. |
| `table_count` / `global_count` | Declared tables and globals. |
| `start` | Start function index, when the module declares one. |
| `data_segment_count` | Number of data segments. |
| `data_segments` | Bounded per-segment sizes; contents are never retained. |
| `element_segment_count` | Number of element segments. |
| `element_segments` | Bounded per-segment item counts. |
| `tables` | Element type, initial size, and maximum size. |
| `memories` | Initial/maximum pages, shared flag, and the `memory64` flag. |
| `imports` | Module, name, and kind, in module order. |
| `exports` | Name and kind, in module order. |
| `custom_sections` | Name and payload size, in module order. |
| `name` | Module, function, and type names from the `name` section, when present; omitted otherwise. |
| `producers` | Build provenance from the `producers` section (`language`, `processed-by`, `sdk`), when present and valid. |
| `code_section_bytes` | Size of the code section. |
| `has_contract_spec` | Whether `contractspecv0` is present. |
| `contract_spec_bytes` | Size of that section, if present. |
| `truncated` | Whether a list hit a configured limit. |

## Safety and limits

- Inspection never executes the module.
- Input is bounded to 64 MiB (`MAX_WASM_BYTES`).
- Import/export/custom-section, table, data, and element lists are bounded;
  `truncated` reports clipping. Counts are still read from section headers, so
  they stay exact when a summary list is clipped.
- Malformed input returns a structured error (`wasm error`).
- The `name` section is decoded with `wasmparser`'s name-section reader. Module,
  function, and type names are reported when present; unsupported and malformed
  subsections are skipped rather than failing inspection. Function and type maps
  are bounded by `MAX_NAME_ENTRIES`, and individual names longer than
  `MAX_NAME_BYTES` are skipped. Clipping is reported by `truncated`.
- The `producers` section is decoded into bounded lists (at most
  `MAX_PRODUCER_ENTRIES` entries across all categories); its absence is not an
  error, and tool names are preserved verbatim.
- A 64-bit linear memory (`memory64` proposal) is reported rather than rejected.
  Soroban contracts target 32-bit linear memory, so `inspect --security` warns
  on `artifact.memory64`.
- WebAssembly **component-model** binaries are out of scope. Their preamble is
  detected and rejected with an `unsupported` error naming components, rather
  than a confusing parse failure. Only core WASM modules are inspected.

## Ordering

Imports, exports, and custom sections are reported in module order, which is
meaningful for WASM. Counts are exact except when `truncated` is true.

## Security heuristics

`inspect --security` merges bounded artifact heuristics (for example: no code
section, no `contractspecv0`, truncated listing) with interface heuristics. See
[security.md](security.md). These are not an audit.

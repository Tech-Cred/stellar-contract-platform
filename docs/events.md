# Events

`events` decodes a fixture of concrete emitted events and filters it. This is
different from the *declared* events in the contract specification.

Each normalized event retains both representations of every topic and its data:
`topics` and `data` contain stable rendered JSON, while `raw_topics` and
`raw_data` contain the original base64 `ScVal` XDR for independent decoding and
verification. Raw fixture and RPC values are preserved verbatim after trimming;
values extracted from a raw `ContractEvent` are canonically re-encoded. A single
raw topic or data value is limited to 1 MiB.

## Fixture format

```json
{
  "events": [
    {
      "contractId": "C...",
      "ledger": 123,
      "txHash": "abcd",
      "type": "contract",
      "topics": ["<base64 ScVal>", "<base64 ScVal>"],
      "data": "<base64 ScVal>"
    }
  ]
}
```

A bare array is also accepted. `topics` and `data` are optional; `type` defaults
to `contract`. Topics and data are decoded as Stellar `ScVal` XDR and rendered to
JSON.

## Event types

Stellar has three event types, and `events` normalizes all of them to the same
`EventRecord` shape. `event_type` is always lowercase, whether it came from a
fixture (`type` is trimmed and lowercased) or from raw XDR (the enum name is
lowercased). Normalization is deterministic: the same input always yields the
same record.

| Type | Emitted by | `contract_id` | Typical topics |
| ---- | ---------- | ------------- | -------------- |
| `system` | The host, for protocol-level events. | Usually absent. | Protocol-defined symbols. |
| `contract` | A contract, through `contractevents`. | Present for the emitting contract. | Application events such as `transfer`. |
| `diagnostic` | The host, when diagnostics are enabled. | Present when the event is tied to a contract, otherwise absent. | Diagnostic kind, for example `fn_call`, `log`, or `error`. |

Diagnostic events are not application events: they describe host execution (call
traces, logs, errors) and may appear without a contract id. Their topics, data,
and rendered JSON are decoded and emitted exactly like the other types, so
consumers can rely on one record shape. A diagnostic event is distinguished only
by `event_type: "diagnostic"`; no fields are reinterpreted or dropped.


## Raw `ContractEvent` XDR

A base64 `ContractEvent` blob can be passed directly instead of a fixture
document. It can also appear as an `xdr` field on a fixture entry (`eventXdr` is
accepted as an alias):

```json
{
  "events": [
    {
      "xdr": "<base64 ContractEvent>",
      "ledger": 123,
      "txHash": "abcd"
    }
  ]
}
```

The contract id, event type, topics, and data are normalized exactly like a
fixture entry. `ledger` and `txHash` are optional metadata that only a fixture
can provide; a bare blob leaves them `null`. Malformed base64 or XDR returns a
structured decode error.

## Filtering

Filters are applied in this order: contract, then type, then topic, then limit.
An omitted filter is a no-op.

| Flag | Behavior |
| ---- | -------- |
| `--contract <ID>` | Exact contract id match. Events without a contract id, including diagnostic events emitted outside a contract, never match. |
| `--topic <FILTER>` | Structured or legacy topic filter; see the syntax below. Works for diagnostic topics such as `fn_call` and `log`. |
| `--type <TYPE>` | Case-insensitive event type match. `--type diagnostic` selects diagnostic events regardless of their contract id. |
| `--limit <N>` | Applied last. |

### Topic filter syntax

| Form | Match |
| ---- | ----- |
| `--topic transfer` | Legacy substring match against extracted topic text (symbols/strings) or rendered topics. |
| `--topic name=transfer` | Exact match against any extracted topic symbol or string. |
| `--topic index0=transfer` | Exact match against the extracted symbol at zero-based position `0`. |

Indices apply to `topic_symbols`, not the raw `topics` array. Only `ScVal::Symbol`
and `ScVal::String` topics are extracted, so a non-symbol topic before a symbol
does not consume an index. For example, a raw integer topic followed by
`symbol("transfer")` has `index0=transfer`, not `index1=transfer`. Structured
forms never fall back to rendered topic JSON, so matches are deterministic.
Empty values, unknown prefixes such as `idx0=`, non-numeric or negative indices,
and index overflow are rejected with a structured `invalid_input` error.

Diagnostic events are filtered by the same rules as system and contract events.
The only behavior worth calling out is the contract filter: it matches the
`contract_id` field exactly, so a diagnostic event with no contract id is kept
only when no contract filter is supplied. Type and topic filters work on the
normalized fields and do not special-case diagnostic events.

## Limitations

- Declared events (specification) and emitted events (fixture) are distinct.
  Declared events describe *shape*; fixtures contain *instances*.
- Topics that are not symbols or strings are ignored by structured filters. The
  legacy bare-text filter still matches their rendered JSON.
- Historical event retrieval is opt-in and offline-only in the test suite. The
  `events --rpc-fixture` path reads a mock `getEvents` response, normalizes
  `contractId`/`ledger`/`txHash`/`type`/`topic`/`value`, and paginates using the
  returned cursor. Live network fetching is not wired into the CLI yet; fixtures
  remain the supported deterministic path.

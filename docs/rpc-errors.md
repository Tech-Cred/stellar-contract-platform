# JSON-RPC error taxonomy

`observatory-rpc` turns JSON-RPC error responses into a typed
`observatory_core::RpcError`. Callers can branch on `RpcError::kind()` without
parsing the human-readable message, while `RpcError::code()` (also available as
`raw_code()`) preserves the exact code the server sent.

```rust
let error = client.get_network().unwrap_err();
if let Some(rpc) = error.rpc_error() {
    match rpc.kind() {
        RpcErrorKind::MethodNotFound => { /* method is not supported */ }
        RpcErrorKind::InvalidParams => { /* fix the request */ }
        RpcErrorKind::Server => { /* provider-side failure; log rpc.code() */ }
        other => { /* unknown or transport failure */ }
    }
}
```

## Health probe

`RpcClient::get_health()` wraps the published `getHealth` method and returns a
typed `HealthResult`: `status`, `latest_ledger`, `latest_ledger_close_time`,
`oldest_ledger`, `oldest_ledger_close_time`, and `ledger_retention_window`.
These are the documented fields only; an incomplete or malformed result is a
decode error rather than a partially-filled report. JSON-RPC failures use the
same typed error mapping as every other method.

## Known kinds

| Kind | Code | Meaning |
| ---- | ---- | ------- |
| `transport` | none | The request never produced a JSON-RPC response (I/O or transport failure). |
| `parse` | `-32700` | The server could not parse the JSON request. |
| `invalid_request` | `-32600` | The request envelope was not valid JSON-RPC. |
| `method_not_found` | `-32601` | The requested method does not exist. |
| `invalid_params` | `-32602` | The method parameters were invalid. |
| `internal` | `-32603` | The server reported an internal error. |
| `server` | `-32000` to `-32099` | Reserved server-defined error range. |
| `unknown` | any other value, or none | A provider-specific code or an error object without a code. |

## Preservation rules

- Unknown codes are **not** remapped: `kind` is `unknown` and `code` keeps the
  original numeric value (for example `-77777`).
- A missing `code` field is kept as `None`; the client never invents `0`.
- Error reports expose the same information through the optional `rpc_kind` and
  `rpc_code` fields. Those fields are omitted for non-RPC errors, so existing
  error JSON remains unchanged.
- `RpcErrorKind::as_str()` returns the stable snake_case string used in JSON.

## Retry policy

`observatory_rpc::RetryPolicy` bounds automatic retries for transient
failures. Use `RpcClient::call_with_retry(method, params, &policy, &clock)` or
the free `retry_call` function; the plain `call` and typed helpers never retry
implicitly.

- **What is retried:** transport failures (`RpcErrorKind::Transport`) and
  server-side JSON-RPC errors (`internal`, `server`). Client errors (`parse`,
  `invalid_request`, `method_not_found`, `invalid_params`) and non-RPC errors
  are returned immediately, because retrying them cannot succeed.
- **Backoff:** the delay after the first failed attempt is `base_delay`, then
  doubles up to `max_delay`. `RetryPolicy::delay_for(n)` exposes it.
- **Bound:** `max_attempts` counts the first call. With the default policy
  (`DEFAULT_MAX_RETRY_ATTEMPTS = 3`, base 200 ms, cap 2 s) a transient failure
  is attempted at most three times with 200 ms and 400 ms of backoff.
- **Determinism:** sleeping goes through the `Clock` trait. Tests inject a
  recording clock and assert the exact delays without waiting; production uses
  `SystemClock`.
- **Failure surfacing:** when attempts are exhausted, the last error is
  returned unchanged, including its typed kind and raw code.

## Adding a new known code

Add the mapping to `RpcErrorKind::from_code`, extend the table above, and add a
unit test. Do not narrow the `server` range; provider-specific values inside
`-32000..=-32099` stay classified as `server` and keep their raw code.

# Observatory Python client

A standard-library-only, typed client for the Observatory v1 REST API. It mirrors
the published OpenAPI document and preserves the API's stable error codes.

## Install

```bash
pip install ./sdks/python
```

Python 3.11 or newer is required. There are no runtime dependencies.

## Quick start

```python
from observatory_client import Client, InspectRequest

client = Client(
    "http://127.0.0.1:8080",
    api_key="sco_<id>_<secret>",
    timeout=10.0,
)

wasm = open("contract.wasm", "rb").read()
report = client.inspect(InspectRequest(wasm=wasm, security=True))
print(report["wasm"]["artifact_sha256"])
```

Analysis endpoints require `run_analysis`; use a `developer`, `maintainer`, or
`admin` key. The key is sent as `X-API-Key` and is never written to disk by this
client. Public endpoints (`health`, `readiness`, `version`) work without a key.

## Requests and responses

Request bodies are frozen dataclasses:

- `InspectRequest(wasm, security=False)`
- `WasmRequest(wasm)`
- `DiffRequest(old_wasm, new_wasm)`
- `CompatibilityRequest(old_wasm, new_wasm, policy="strict")`

Response data is typed with `TypedDict` definitions such as `InspectResponse`,
`InterfaceDiff`, and `CompatibilityAssessment`. The client validates the report
envelope (`kind` and `schema_version`) and returns `data`; unknown response
fields are preserved.

```python
from observatory_client import CompatibilityRequest, DiffRequest

diff = client.diff(DiffRequest(old_wasm=old, new_wasm=new))
print(diff["summary"]["breaking"])

assessment = client.compatibility(
    CompatibilityRequest(old_wasm=old, new_wasm=new, policy="strict")
)
for reason in assessment["reasons"]:
    print(reason["breaking"], reason["path"], reason["message"])
```

`policy` is the API preset `strict` or `lenient`. The finer-grained
`enum_case_addition_is_breaking` rule is a policy document used by the CLI and
project configuration; it is documented in [`docs/compatibility.md`](../../docs/compatibility.md).

## Timeouts, retries, and bounds

`Client` rejects invalid configuration at construction time:

- `timeout` (default `30.0`, maximum `300`) applies to every request.
- `max_response_bytes` (default 8 MiB, maximum 64 MiB) caps each response body.
- `max_retries` defaults to `0`: retries are opt-in and capped at `5`. Only
  transport failures, timeouts, and retryable API responses (`408`, `429`,
  `5xx`, or `rate_limited`/`internal`/`rpc`/`verification`/`io`) are retried.
- Retries use bounded exponential backoff (`backoff`, `max_backoff`).

```python
from observatory_client import Client

client = Client(
    "https://observatory.example",
    api_key="sco_<id>_<secret>",
    timeout=5.0,
    max_retries=2,
    backoff=0.05,
    max_backoff=0.2,
)
```

The client does not log requests, headers, bodies, or keys. Error messages are
redacted before they are surfaced.

## Errors

Every failure derives from `ObservatoryError`:

- `ApiError` carries `status`, stable `code`, `message`, optional `request_id`,
  and optional `rpc_kind`/`rpc_code`.
- `TimeoutError`, `TransportError`, `DecodeError`, and `ConfigError` cover the
  other failure modes.

```python
from observatory_client import ApiError, ApiErrorCode, ObservatoryError

try:
    client.health()
except ApiError as error:
    if error.code == ApiErrorCode.UNAUTHORIZED:
        print("check the API key")
except ObservatoryError as error:
    print("request failed:", error)
```

Unknown codes from newer servers are preserved as strings rather than rejected.

## Development

```bash
cd sdks/python
python -m pytest
ruff check .
mypy .
```

The default test run uses injected transports and never opens a socket. The
integration tests are opt-in, bind a real `api serve` process to a loopback
port, and use a short timeout with a bounded startup wait:

```bash
cargo build -p observatory-cli
RUN_OBSERVATORY_INTEGRATION=1 OBSERVATORY_BIN=../../target/debug/stellar-contract-platform \
  python -m pytest tests/test_integration.py
```

`OBSERVATORY_BIN` is optional when the debug binary is at the workspace default
path. The server uses an in-memory key store and is terminated after the tests;
the test API key is ephemeral and is never printed or persisted.

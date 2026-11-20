# Signed webhook delivery

The platform delivers webhook events with HMAC-SHA256 signatures and bounded
retries. Registration endpoints are tracked in issue #47; this page describes the
delivery contract that a registered endpoint receives.

## Headers

Every attempt carries:

| Header | Meaning |
| ------ | ------- |
| `X-Observatory-Signature` | `sha256=<hex HMAC>` over `<timestamp>.<body>`. |
| `X-Observatory-Timestamp` | Unix timestamp in seconds used in the signature. |
| `X-Observatory-Delivery-Id` | Unique delivery id, identical across retries. |
| `X-Observatory-Event` | Event name, for example `scan.completed`. |
| `Content-Type` | `application/json`. |

The secret is never sent. Only the signature and timestamp are.

## Verify a delivery

The signed message is the decimal timestamp, a literal `.`, and the exact request
body bytes.

```python
import hashlib
import hmac

def verify(secret: str, timestamp: str, body: bytes, header: str) -> bool:
    provided = header.removeprefix("sha256=")
    message = timestamp.encode() + b"." + body
    expected = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided, expected)

# Reject a timestamp outside your tolerance window to limit replay, even though
# the delivery id is stable across retries.
```

Verification rules:

1. Compare the signature in constant time.
2. Reject stale or future timestamps outside your tolerance (for example five
   minutes).
3. Deduplicate on `X-Observatory-Delivery-Id`; retries reuse the same id.

A tampered body, a changed timestamp, or the wrong secret fails verification.

## Retries

- `2xx` means delivered.
- `408`, `429`, and `5xx` are transient and retried.
- A transport error is retried.
- Any other `4xx` is a permanent failure and is not retried.
- Backoff starts at the configured `initial_backoff`, doubles per attempt, and is
  capped by `max_backoff`. `max_attempts` is bounded to `1..=10`.

Each attempt records its timestamp, HTTP status or transport error, and the next
retry time. The final `DeliveryOutcome` reports `delivered` or `failed`.

## Transport

The built-in `HttpTransport` handles `http://` loopback receivers so local tests
need no network access. Non-loopback plaintext delivery is opt-in
(`allow_insecure_http`) and is intended for a trusted TLS-terminating proxy.
HTTPS should be supplied by a TLS-capable `WebhookTransport` implementation.

Payloads are bounded to 256 KiB and event names to 128 bytes. Secrets are never
logged; `WebhookRegistration` redacts its secret in `Debug` output.

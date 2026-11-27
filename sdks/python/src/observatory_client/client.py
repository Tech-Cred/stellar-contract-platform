"""Bounded Python client for the Observatory v1 REST API.

The client uses only the standard library. Requests carry an API key when one is
configured, every request has a timeout and response-size cap, and retries are
opt-in and bounded. No request body, header, or key is written to disk or logged.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Callable
from http.client import HTTPException
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .errors import (
    ApiError,
    ConfigError,
    DecodeError,
    TransportError,
    redact,
)
from .errors import (
    TimeoutError as ClientTimeoutError,
)
from .models import (
    AuditReport,
    CompatibilityAssessment,
    CompatibilityRequest,
    DiffRequest,
    FingerprintResponse,
    Health,
    InspectRequest,
    InspectResponse,
    InterfaceDiff,
    JsonObject,
    Readiness,
    SpecResponse,
    VersionInfo,
    WasmRequest,
)

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ALLOWED_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_ALLOWED_RETRIES = 5


class ReadableResponse(Protocol):
    """Any response-like object with a bounded byte stream."""

    def read(self, amount: int = -1) -> bytes: ...


class HttpResponse(ReadableResponse, Protocol):
    """The subset of a successful HTTP response the client consumes."""

    status: int
    headers: Any

    def close(self) -> None: ...


Opener = Callable[[Request, float], HttpResponse]
Sleep = Callable[[float], None]


def _urlopen(request: Request, timeout: float) -> HttpResponse:
    """Adapt ``urlopen`` to the client's two-argument opener protocol."""
    return cast(HttpResponse, urlopen(request, timeout=timeout))


class Client:
    """A typed, bounded client for a single Observatory instance."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = 0,
        backoff: float = 0.1,
        max_backoff: float = 2.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        opener: Opener | None = None,
        sleep: Sleep | None = None,
    ) -> None:
        parsed = urlparse(base_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ConfigError("base_url must be an http:// or https:// URL")
        if parsed.query or parsed.fragment:
            raise ConfigError("base_url must not contain a query or fragment")
        if not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ConfigError("timeout must be greater than zero and at most 300 seconds")
        if not 0 <= max_retries <= MAX_ALLOWED_RETRIES:
            raise ConfigError(f"max_retries must be between 0 and {MAX_ALLOWED_RETRIES}")
        if not math.isfinite(backoff) or not 0 < backoff <= 1:
            raise ConfigError("backoff must be greater than zero and at most one second")
        if not math.isfinite(max_backoff) or not backoff <= max_backoff <= 30:
            raise ConfigError("max_backoff must be at least backoff and at most 30 seconds")
        if not 1 <= max_response_bytes <= MAX_ALLOWED_RESPONSE_BYTES:
            raise ConfigError("max_response_bytes must be between 1 and 64 MiB")
        if api_key is not None and not api_key.strip():
            raise ConfigError("api_key must not be empty")

        self._base_url = base_url.strip().rstrip("/")
        self._api_key = api_key.strip() if api_key is not None else None
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff = backoff
        self._max_backoff = max_backoff
        self._max_response_bytes = max_response_bytes
        self._opener = opener or _urlopen
        self._sleep = sleep or time.sleep

    def health(self) -> Health:
        """Public liveness check."""
        return cast(Health, self._request("health", "GET", "/api/v1/health"))

    def readiness(self) -> Readiness:
        """Public readiness check."""
        return cast(Readiness, self._request("readiness", "GET", "/api/v1/readiness"))

    def version(self) -> VersionInfo:
        """Public tool and API version information."""
        return cast(VersionInfo, self._request("version", "GET", "/api/v1/version"))

    def inspect(self, request: InspectRequest) -> InspectResponse:
        """Inspect one contract artifact."""
        return cast(
            InspectResponse,
            self._request("inspect", "POST", "/api/v1/contracts/inspect", request.payload()),
        )

    def spec(self, request: WasmRequest) -> SpecResponse:
        """Normalize a contract specification."""
        return cast(
            SpecResponse,
            self._request("spec", "POST", "/api/v1/contracts/spec", request.payload()),
        )

    def diff(self, request: DiffRequest) -> InterfaceDiff:
        """Diff two canonical interfaces."""
        return cast(
            InterfaceDiff,
            self._request("diff", "POST", "/api/v1/contracts/diff", request.payload()),
        )

    def compatibility(self, request: CompatibilityRequest) -> CompatibilityAssessment:
        """Assess compatibility under a named policy preset."""
        return cast(
            CompatibilityAssessment,
            self._request(
                "compat",
                "POST",
                "/api/v1/contracts/compatibility",
                request.payload(),
            ),
        )

    def fingerprint(self, request: WasmRequest) -> FingerprintResponse:
        """Compute artifact and interface fingerprints."""
        return cast(
            FingerprintResponse,
            self._request(
                "fingerprint",
                "POST",
                "/api/v1/contracts/fingerprint",
                request.payload(),
            ),
        )

    def security(self, request: WasmRequest) -> AuditReport:
        """Run bounded security heuristics."""
        return cast(
            AuditReport,
            self._request("security", "POST", "/api/v1/contracts/security", request.payload()),
        )

    def _request(
        self,
        kind: str,
        method: str,
        path: str,
        payload: JsonObject | None = None,
    ) -> JsonObject:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers: dict[str, str] = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._api_key is not None:
            headers["X-API-Key"] = self._api_key

        request = Request(
            f"{self._base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )

        for attempt in range(self._max_retries + 1):
            try:
                return self._once(request, kind)
            except (ApiError, ClientTimeoutError, TransportError) as error:
                retryable = (
                    error.retryable
                    if isinstance(error, ApiError)
                    else isinstance(error, (ClientTimeoutError, TransportError))
                )
                if not retryable or attempt == self._max_retries:
                    raise
                self._sleep(min(self._backoff * (2**attempt), self._max_backoff))

        raise AssertionError("unreachable")

    def _once(self, request: Request, kind: str) -> JsonObject:
        try:
            response = self._opener(request, self._timeout)
        except HTTPError as error:
            raise self._api_error(
                error.code,
                self._read_bounded(error),
                error.headers,
            ) from None
        except TimeoutError as error:
            raise ClientTimeoutError(redact(str(error))) from None
        except (URLError, HTTPException) as error:
            raise TransportError(redact(str(error))) from None

        try:
            raw = self._read_bounded(response)
            status = response.status
            headers = response.headers
        finally:
            close = getattr(response, "close", None)
            if close is not None:
                close()

        if not 200 <= status < 300:
            raise self._api_error(status, raw, headers)

        return self._parse_envelope(raw, kind)

    def _read_bounded(self, source: ReadableResponse) -> bytes:
        raw = source.read(self._max_response_bytes + 1)
        if len(raw) > self._max_response_bytes:
            raise DecodeError("response exceeded the configured size limit")
        return raw

    def _parse_envelope(self, raw: bytes, kind: str) -> JsonObject:
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DecodeError(redact(f"invalid JSON response: {error}")) from None
        if not isinstance(envelope, dict):
            raise DecodeError("response was not a report envelope")
        if envelope.get("kind") != kind:
            got = envelope.get("kind")
            raise DecodeError(f"expected kind `{kind}`, got `{got!r}`")
        if not isinstance(envelope.get("schema_version"), str):
            raise DecodeError("response envelope is missing schema_version")
        data = envelope.get("data")
        if not isinstance(data, dict):
            raise DecodeError("response envelope is missing a data object")
        return cast(JsonObject, data)

    def _api_error(self, status: int, raw: bytes, headers: Any) -> ApiError:
        request_id = headers.get("X-Request-Id") if headers is not None else None
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, DecodeError):
            body = None
        if not isinstance(body, dict):
            return ApiError(status, "unknown", "non-JSON error response", request_id=request_id)

        code = body.get("code")
        message = body.get("message")
        if not isinstance(code, str) or not isinstance(message, str):
            return ApiError(status, "unknown", "malformed error response", request_id=request_id)
        rpc_kind = body.get("rpc_kind")
        rpc_code = body.get("rpc_code")
        return ApiError(
            status,
            code,
            message,
            request_id=request_id if isinstance(request_id, str) else None,
            rpc_kind=rpc_kind if isinstance(rpc_kind, str) else None,
            rpc_code=rpc_code if isinstance(rpc_code, int) else None,
        )


__all__ = ["Client", "DEFAULT_MAX_RESPONSE_BYTES", "DEFAULT_TIMEOUT", "Opener", "Sleep"]

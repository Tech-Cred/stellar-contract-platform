"""Unit tests for the Python client using injected transports."""

from __future__ import annotations

import io
import json
from base64 import b64encode
from email.message import Message
from typing import Any, cast
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from observatory_client import (
    ApiError,
    ApiErrorCode,
    Client,
    ConfigError,
    DecodeError,
    InspectRequest,
)
from observatory_client import (
    TimeoutError as ClientTimeoutError,
)


class FakeResponse:
    """A minimal response object with a bounded body."""

    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._body = body
        self.status = status
        self.headers = headers or {}
        self.closed = False

    def read(self, amount: int = -1) -> bytes:
        """Return the body, optionally capped."""
        return self._body if amount < 0 else self._body[:amount]

    def close(self) -> None:
        """Record that the response was closed."""
        self.closed = True


def envelope(kind: str, data: dict[str, Any]) -> bytes:
    """Build a valid report envelope for a fake response."""
    return json.dumps(
        {
            "schema_version": "1.0",
            "kind": kind,
            "tool": "stellar-contract-platform",
            "version": "0.1.0",
            "data": data,
        }
    ).encode()


def headers_of(request: Request) -> dict[str, str]:
    """Normalize request header names for assertions."""
    return {name.lower(): value for name, value in request.header_items()}


def test_health_sends_api_key_and_returns_typed_data() -> None:
    seen: dict[str, Any] = {}

    def opener(request: Request, timeout: float) -> FakeResponse:
        seen["headers"] = headers_of(request)
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        return FakeResponse(envelope("health", {"status": "ok"}))

    client = Client("http://127.0.0.1:8080/", api_key="sco_test_secret", timeout=1.5, opener=opener)
    assert client.health() == {"status": "ok"}
    assert seen["headers"]["x-api-key"] == "sco_test_secret"
    assert seen["headers"]["accept"] == "application/json"
    assert seen["url"] == "http://127.0.0.1:8080/api/v1/health"
    assert seen["timeout"] == 1.5


def test_request_models_encode_wasm_as_base64() -> None:
    bodies: list[dict[str, Any]] = []

    def opener(request: Request, _timeout: float) -> FakeResponse:
        assert request.data is not None
        bodies.append(json.loads(cast(bytes, request.data)))
        return FakeResponse(envelope("inspect", {"wasm": {}, "interface": None, "audit": None}))

    wasm = b"\x00asm\x01\x00\x00\x00"
    client = Client("http://127.0.0.1:8080", opener=opener)
    client.inspect(InspectRequest(wasm=wasm, security=True))

    assert bodies == [
        {"wasm_base64": b64encode(wasm).decode("ascii"), "security": True},
    ]


def test_api_error_exposes_stable_code_and_request_id() -> None:
    def opener(request: Request, _timeout: float) -> FakeResponse:
        body = json.dumps({"code": "unauthorized", "message": "bad sco_test_secret"}).encode()
        headers = Message()
        headers["X-Request-Id"] = "req-1"
        raise HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            headers,
            io.BytesIO(body),
        )

    client = Client("http://127.0.0.1:8080", api_key="sco_test_secret", opener=opener)
    with pytest.raises(ApiError) as caught:
        client.health()

    error = caught.value
    assert error.status == 401
    assert error.code == ApiErrorCode.UNAUTHORIZED
    assert error.request_id == "req-1"
    assert error.retryable is False
    assert "sco_test_secret" not in str(error)


def test_retries_are_opt_in_and_bounded() -> None:
    attempts = 0
    sleeps: list[float] = []

    def opener(_request: Request, _timeout: float) -> FakeResponse:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            body = json.dumps({"code": "rate_limited", "message": "slow down"}).encode()
            return FakeResponse(body, status=503)
        return FakeResponse(envelope("health", {"status": "ok"}))

    client = Client(
        "http://127.0.0.1:8080",
        max_retries=2,
        backoff=0.01,
        max_backoff=0.02,
        opener=opener,
        sleep=sleeps.append,
    )
    assert client.health() == {"status": "ok"}
    assert attempts == 3
    assert sleeps == [0.01, 0.02]


def test_no_retry_by_default() -> None:
    attempts = 0

    def opener(_request: Request, _timeout: float) -> FakeResponse:
        nonlocal attempts
        attempts += 1
        body = json.dumps({"code": "rate_limited", "message": "slow down"}).encode()
        return FakeResponse(body, status=429)

    client = Client("http://127.0.0.1:8080", opener=opener)
    with pytest.raises(ApiError) as caught:
        client.health()

    assert caught.value.code == ApiErrorCode.RATE_LIMITED
    assert attempts == 1


def test_non_retryable_error_is_not_retried() -> None:
    attempts = 0

    def opener(_request: Request, _timeout: float) -> FakeResponse:
        nonlocal attempts
        attempts += 1
        body = json.dumps({"code": "bad_request", "message": "invalid input"}).encode()
        return FakeResponse(body, status=400)

    client = Client("http://127.0.0.1:8080", max_retries=5, opener=opener)
    with pytest.raises(ApiError):
        client.health()
    assert attempts == 1


def test_oversized_response_is_rejected() -> None:
    def opener(_request: Request, _timeout: float) -> FakeResponse:
        return FakeResponse(envelope("health", {"status": "ok"}))

    client = Client("http://127.0.0.1:8080", max_response_bytes=8, opener=opener)
    with pytest.raises(DecodeError, match="size limit"):
        client.health()


def test_transport_timeout_becomes_client_error() -> None:
    def opener(_request: Request, _timeout: float) -> FakeResponse:
        raise TimeoutError

    client = Client("http://127.0.0.1:8080", opener=opener)
    with pytest.raises(ClientTimeoutError):
        client.health()


def test_wrong_envelope_kind_is_a_decode_error() -> None:
    def opener(_request: Request, _timeout: float) -> FakeResponse:
        return FakeResponse(envelope("version", {"status": "ok"}))

    client = Client("http://127.0.0.1:8080", opener=opener)
    with pytest.raises(DecodeError, match="expected kind"):
        client.health()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base_url": "127.0.0.1:8080"},
        {"base_url": "http://127.0.0.1:8080?x=1"},
        {"timeout": 0},
        {"timeout": 301},
        {"max_retries": 6},
        {"max_response_bytes": 65 * 1024 * 1024},
        {"api_key": "   "},
    ],
)
def test_invalid_configuration_is_rejected(kwargs: dict[str, Any]) -> None:
    options = {"base_url": "http://127.0.0.1:8080"} | kwargs
    with pytest.raises(ConfigError):
        Client(**options)

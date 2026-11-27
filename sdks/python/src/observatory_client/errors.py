"""Typed, stable errors for the Observatory Python client."""

from __future__ import annotations

import re
from enum import StrEnum

_TOKEN = re.compile(r"sco_[A-Za-z0-9_-]+")

RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
RETRYABLE_CODES = frozenset(
    {
        "rate_limited",
        "internal",
        "rpc",
        "verification",
        "io",
    }
)


def redact(text: str) -> str:
    """Remove API-key-shaped tokens from text surfaced to callers."""
    return _TOKEN.sub("<redacted>", text)


class ApiErrorCode(StrEnum):
    """Stable codes published by ``GET /api/v1/errors``."""

    BAD_REQUEST = "bad_request"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    UNPROCESSABLE_ENTITY = "unprocessable_entity"
    RATE_LIMITED = "rate_limited"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    INTERNAL = "internal"
    INVALID_INPUT = "invalid_input"
    DECODE = "decode"
    WASM = "wasm"
    SPEC = "spec"
    UNSUPPORTED = "unsupported"
    RPC = "rpc"
    VERIFICATION = "verification"
    IO = "io"


class ObservatoryError(Exception):
    """Base class for every client failure."""


class ConfigError(ObservatoryError):
    """The client configuration is invalid."""


class TransportError(ObservatoryError):
    """The transport failed before a complete response was received."""


class TimeoutError(ObservatoryError):  # noqa: A001 - shadows a builtin by design
    """A request exceeded the configured timeout."""


class DecodeError(ObservatoryError):
    """The response was not the expected report envelope."""


class ApiError(ObservatoryError):
    """A non-success API response with a stable error code."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        request_id: str | None = None,
        rpc_kind: str | None = None,
        rpc_code: int | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.message = redact(message)
        self.request_id = request_id
        self.rpc_kind = rpc_kind
        self.rpc_code = rpc_code
        super().__init__(f"{status} {code}: {self.message}")

    @property
    def retryable(self) -> bool:
        """Whether repeating the same request may succeed."""
        return self.status in RETRYABLE_STATUSES or self.code in RETRYABLE_CODES

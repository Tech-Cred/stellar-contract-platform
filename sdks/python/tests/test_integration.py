"""Opt-in integration tests against a real loopback `api serve` process.

Set ``RUN_OBSERVATORY_INTEGRATION=1`` to run these tests. They use an ephemeral
in-memory key, a short client timeout, a bounded startup wait, and no log files.
"""

from __future__ import annotations

import os
import secrets
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from observatory_client import (
    ApiError,
    ApiErrorCode,
    Client,
    CompatibilityRequest,
    DiffRequest,
    InspectRequest,
    ObservatoryError,
)

ROOT = Path(__file__).resolve().parents[3]
RUN_INTEGRATION = os.environ.get("RUN_OBSERVATORY_INTEGRATION", "").lower() in {
    "1",
    "true",
    "yes",
}

pytestmark = pytest.mark.skipif(
    not RUN_INTEGRATION,
    reason="set RUN_OBSERVATORY_INTEGRATION=1 to start a real api serve process",
)


def free_loopback_port() -> int:
    """Ask the OS for an available loopback port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def default_binary() -> Path:
    """Locate the debug CLI built by cargo test."""
    suffix = ".exe" if os.name == "nt" else ""
    return ROOT / "target" / "debug" / f"stellar-contract-platform{suffix}"


@pytest.fixture(scope="module")
def server() -> Iterator[tuple[str, str]]:
    """Run the real API on loopback with an ephemeral developer key."""
    binary = Path(os.environ.get("OBSERVATORY_BIN", str(default_binary())))
    if not binary.is_file():
        pytest.skip(f"CLI binary not found at {binary}")

    port = free_loopback_port()
    base_url = f"http://127.0.0.1:{port}"
    api_key = f"sco_sdk_{secrets.token_hex(8)}"
    process = subprocess.Popen(  # noqa: S603 - fixed local binary path
        [
            str(binary),
            "api",
            "serve",
            "--bind",
            f"127.0.0.1:{port}",
            "--key",
            f"developer:{api_key}",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        deadline = time.monotonic() + 10
        last_error: ObservatoryError | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail("api serve exited before becoming healthy")
            try:
                Client(base_url, timeout=0.5).health()
                break
            except ObservatoryError as error:
                last_error = error
                time.sleep(0.05)
        else:
            pytest.fail(f"api serve did not become healthy: {last_error}")
        yield base_url, api_key
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def fixture_wasm(name: str) -> bytes:
    """Read a committed compatibility fixture."""
    return (ROOT / "fixtures" / "compat" / "enum-addition" / name).read_bytes()


def test_real_server_typed_round_trip(server: tuple[str, str]) -> None:
    """Exercise typed responses against the real HTTP server."""
    base_url, api_key = server
    client = Client(base_url, api_key=api_key, timeout=2.0)

    assert client.version()["api_version"] == "v1"
    assert isinstance(client.readiness()["auth_required"], bool)

    old = fixture_wasm("baseline.wasm")
    new = fixture_wasm("head.wasm")
    report = client.inspect(InspectRequest(wasm=old, security=True))
    assert report["wasm"]["has_contract_spec"] is True

    diff = client.diff(DiffRequest(old_wasm=old, new_wasm=new))
    assert any(change["kind"] == "enum_case_added" for change in diff["changes"])

    assessment = client.compatibility(
        CompatibilityRequest(old_wasm=old, new_wasm=new, policy="strict")
    )
    assert assessment["status"] == "incompatible"
    assert assessment["policy"]["enum_case_addition_is_breaking"] is True


def test_real_server_unauthenticated_error_code(server: tuple[str, str]) -> None:
    """The API rejects analysis requests without a key with a stable code."""
    base_url, api_key = server
    client = Client(base_url, timeout=2.0)

    with pytest.raises(ApiError) as caught:
        client.inspect(InspectRequest(wasm=fixture_wasm("baseline.wasm")))

    assert caught.value.code == ApiErrorCode.UNAUTHORIZED
    assert api_key not in str(caught.value)

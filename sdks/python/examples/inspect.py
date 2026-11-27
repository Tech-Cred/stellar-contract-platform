"""Inspect a contract through a running Observatory API.

Usage:
    OBSERVATORY_API_KEY=sco_... python examples/inspect.py http://127.0.0.1:8080 contract.wasm

The key is read from the environment so it is not placed in shell history or
printed by the example.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from observatory_client import Client, ConfigError, InspectRequest, ObservatoryError


def main(argv: list[str]) -> int:
    """Run the example and return a process exit code."""
    if len(argv) != 2:
        print("usage: inspect.py <BASE_URL> <WASM>", file=sys.stderr)
        return 2
    api_key = os.environ.get("OBSERVATORY_API_KEY")
    if not api_key:
        print("OBSERVATORY_API_KEY is required", file=sys.stderr)
        return 2

    base_url, wasm_path = argv
    try:
        client = Client(base_url, api_key=api_key, timeout=10.0)
        wasm = Path(wasm_path).read_bytes()
        report = client.inspect(InspectRequest(wasm=wasm, security=True))
    except ConfigError as error:
        print(f"invalid client configuration: {error}", file=sys.stderr)
        return 2
    except ObservatoryError as error:
        print(f"request failed: {error}", file=sys.stderr)
        return 1

    print(f"artifact: {report['wasm']['artifact_sha256']}")
    print(f"exports: {len(report['wasm']['exports'])}")
    print(f"contract spec: {'present' if report['wasm']['has_contract_spec'] else 'absent'}")
    if report["audit"] is not None:
        print(f"audit: {report['audit']['status']} ({len(report['audit']['findings'])} findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

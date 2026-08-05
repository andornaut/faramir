"""Thin client for the broker socket.

Deliberately stupid: it builds a request, writes one line, reads one line.
No secret logic lives on this side of the socket -- everything it can see has
already been redacted.
"""

from __future__ import annotations

import json
import os
import socket
from typing import Any

DEFAULT_SOCKET = os.environ.get("SECRETD_SOCKET", "/run/secretd/sock")


class BrokerUnavailable(Exception):
    """Could not talk to secretd."""


def call(request: dict[str, Any], socket_path: str = DEFAULT_SOCKET, timeout: float | None = None) -> dict[str, Any]:
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(socket_path)
    except OSError as exc:
        raise BrokerUnavailable(f"{socket_path}: {exc.strerror or exc}") from exc

    with sock:
        sock.sendall(json.dumps(request).encode("utf-8") + b"\n")
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        chunks = bytearray()
        while b"\n" not in chunks:
            data = sock.recv(65536)
            if not data:
                break
            chunks.extend(data)

    if not chunks.strip():
        raise BrokerUnavailable("broker closed the connection without responding")
    try:
        return json.loads(chunks.split(b"\n", 1)[0].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerUnavailable(f"malformed response from broker: {exc}") from exc

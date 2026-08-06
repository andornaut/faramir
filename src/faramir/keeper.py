"""Holds the age key.  Decrypts on request, and never hands the key out.

The keeper exists so that no process which *executes* a command can reach the
master key.  Losing one credential means rotating one credential; losing the
age key means every managed sops file, retroactively, including every
encrypted blob already in git history.

So it runs as its own uid, execs nothing but ``sops``, and serves exactly one
operation: return the decrypted ref/value map.  There is deliberately no
operation that returns the key.  Adding one would defeat the only reason this
process exists as a separate service.

Protocol: one line of JSON in, one line of JSON out, same shape as the broker
socket.

    -> {"op": "get_values"}                  every managed value
    -> {"op": "get_values", "refs": [...]}   only those refs
    <- {"values": {ref: value, ...}, "errors": [...]}
    <- {"error": {"code": ..., "message": ...}}

The ``refs`` filter exists so that a later "never resident in the broker" list
for break-glass credentials is a configuration change rather than a protocol
change.
"""

from __future__ import annotations

import errno
import grp
import json
import logging
import os
import pwd
import signal
import socket
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator

from .config import Config, ConfigError, KeeperConfig, SecretsConfig

log = logging.getLogger("faramir.keeper")

_SO_PEERCRED = 17  # SO_PEERCRED on Linux
_UCRED = struct.Struct("3i")

# The keeper answers one client (the broker), rarely: on startup, on SIGHUP,
# and when a managed file changes on disk.  Serial handling with a timeout is
# therefore enough, and it keeps the process that holds the key as small as it
# can be.
_CONN_TIMEOUT_SEC = 30.0
_MAX_REQUEST_BYTES = 65536


class KeeperError(Exception):
    """Decryption failed, or the keeper could not be reached."""


# --------------------------------------------------------------------------
# Decryption
# --------------------------------------------------------------------------


def flatten(node: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Walk decrypted YAML/JSON into ``path/to/key`` -> string pairs."""
    if isinstance(node, dict):
        for key, value in node.items():
            # Exactly the top-level 'sops' key, which is sops' own metadata
            # block.  A prefix match at any depth would silently drop real
            # secrets (sops_backup_token, home/sopsuser) from the value set,
            # and a dropped secret is never redacted and never warned about.
            if prefix == "" and str(key) == "sops":
                continue
            yield from flatten(value, f"{prefix}/{key}" if prefix else str(key))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from flatten(value, f"{prefix}/{i}" if prefix else str(i))
    elif isinstance(node, bool) or node is None:
        return  # never secret, and "True"/"False" would redact half the output
    else:
        yield prefix, str(node)


class KeyHolder:
    """Reads the age key once and keeps it in this process only."""

    def __init__(self, config: KeeperConfig) -> None:
        self.config = config
        self._key: str | None = None

    def material(self) -> str | None:
        if self._key is not None:
            return self._key
        candidates = []
        creds = os.environ.get("CREDENTIALS_DIRECTORY")
        if creds and self.config.age_key_credential:
            candidates.append(os.path.join(creds, self.config.age_key_credential))
        if self.config.age_key_file:
            candidates.append(self.config.age_key_file)
        for candidate in candidates:
            try:
                self._key = Path(candidate).read_text("utf-8")
                log.info("loaded age key from %s", candidate)
                return self._key
            except OSError:
                continue
        log.warning("no age key available (tried: %s)", ", ".join(candidates) or "none")
        return None

    def scrub(self, text: str) -> str:
        """Remove key material from ``text``.

        ``sops`` should never print the key back at us, but its stderr is the
        one string that crosses from this process to the broker, and the whole
        point of the split is that the key does not make that trip.
        """
        key = self._key
        if not key:
            return text
        for line in key.splitlines():
            line = line.strip()
            if len(line) > 16 and not line.startswith("#"):
                text = text.replace(line, "«AGE-KEY»")
        return text


def decrypt_all(
    secrets: SecretsConfig, keys: KeyHolder
) -> tuple[dict[str, str], list[str]]:
    """Decrypt every managed file.  Returns ``(values, errors)``."""
    values: dict[str, str] = {}
    errors: list[str] = []
    key = keys.material()
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
    }
    if key:
        env["SOPS_AGE_KEY"] = key

    for path in secrets.files:
        argv = [a.replace("{file}", path) for a in secrets.decrypt_command]
        try:
            proc = subprocess.run(
                argv, capture_output=True, env=env, timeout=60, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(keys.scrub(f"{path}: running {argv[0]} failed: {exc}"))
            continue
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            errors.append(
                keys.scrub(
                    f"{path}: decrypt failed ({proc.returncode}): "
                    f"{detail[-1] if detail else 'no output'}"
                )
            )
            continue
        try:
            tree = json.loads(proc.stdout.decode("utf-8", "replace"))
        except json.JSONDecodeError as exc:
            errors.append(f"{path}: decrypted output is not JSON: {exc}")
            continue
        for ref, value in flatten(tree):
            if ref in values and values[ref] != value:
                log.warning("secret ref %s defined more than once; last wins", ref)
            values[ref] = value
    return values, errors


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------


class Keeper:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.keys = KeyHolder(config.keeper)
        self._stop = False
        self._listener: socket.socket | None = None

    # -- lifecycle ---------------------------------------------------------

    def listen(self) -> socket.socket:
        """Use the systemd-passed socket if present, else bind our own."""
        fds = int(os.environ.get("LISTEN_FDS", "0") or 0)
        listen_pid = int(os.environ.get("LISTEN_PID", "0") or 0)
        if fds and listen_pid == os.getpid():
            if fds != 1:
                raise SystemExit(f"expected exactly 1 socket from systemd, got {fds}")
            sock = socket.socket(fileno=3)  # SD_LISTEN_FDS_START
            sock.setblocking(True)
            log.info("using socket activation fd 3")
        else:
            path = self.config.keeper.socket_path
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.exists(path):
                os.unlink(path)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            previous = os.umask(0o777 ^ self.config.keeper.socket_mode)
            try:
                sock.bind(path)
            finally:
                os.umask(previous)
            os.chmod(path, self.config.keeper.socket_mode)
            sock.listen(8)
            log.info("listening on %s", path)
        self._listener = sock
        return sock

    def serve_forever(self) -> None:
        sock = self._listener or self.listen()
        sock.settimeout(1.0)
        while not self._stop:
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                if self._stop:
                    break
                raise
            self._serve_connection(conn)
        log.info("shutting down")

    def stop(self, *_: Any) -> None:
        self._stop = True

    # -- connection handling ----------------------------------------------

    def _serve_connection(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(_CONN_TIMEOUT_SEC)
            if not self._peer_allowed(conn):
                self._send(conn, _error("forbidden", "peer not authorized"))
                return
            payload = self._read_request(conn)
            if payload is None:
                return
            self._send(conn, self.handle(payload))
        except Exception as exc:  # noqa: BLE001 - one bad connection must not kill us
            log.exception("connection failed")
            try:
                self._send(conn, _error("internal", self.keys.scrub(str(exc))))
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _peer_allowed(self, conn: socket.socket) -> bool:
        try:
            raw = conn.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, _UCRED.size)
            pid, uid, gid = _UCRED.unpack(raw)
        except OSError as exc:
            log.warning("SO_PEERCRED unavailable: %s", exc)
            return False
        # Our own uid covers the single-uid test harness; root is unavoidable.
        if uid in (0, os.getuid()):
            return True
        for name in self.config.keeper.allowed_users:
            try:
                if pwd.getpwnam(name).pw_uid == uid:
                    return True
            except KeyError:
                continue
        for name in self.config.keeper.allowed_groups:
            try:
                entry = grp.getgrnam(name)
            except KeyError:
                continue
            if gid == entry.gr_gid:
                return True
        log.warning("rejected connection from uid=%d gid=%d pid=%d", uid, gid, pid)
        return False

    @staticmethod
    def _read_request(conn: socket.socket) -> Any:
        buf = bytearray()
        while b"\n" not in buf:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                return None
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > _MAX_REQUEST_BYTES:
                return None
        if not buf.strip():
            return None
        try:
            return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    @staticmethod
    def _send(conn: socket.socket, response: dict[str, Any]) -> None:
        conn.sendall(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")

    # -- dispatch ----------------------------------------------------------

    def handle(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return _error("bad_request", "request must be a JSON object")
        op = payload.get("op")
        if op != "get_values":
            # Named explicitly rather than "unknown op": someone reading this
            # error should learn that the key is not obtainable here, not go
            # looking for the operation that returns it.
            return _error(
                "unsupported",
                f"unsupported op {op!r}; the keeper serves 'get_values' only and "
                "has no operation that returns key material",
            )

        refs = payload.get("refs")
        if refs is not None and (
            not isinstance(refs, list) or not all(isinstance(r, str) for r in refs)
        ):
            return _error("bad_request", "'refs' must be a list of strings")

        values, errors = decrypt_all(self.config.secrets, self.keys)
        if refs is not None:
            wanted = set(refs)
            values = {k: v for k, v in values.items() if k in wanted}
        log.info("served %d value(s), %d error(s)", len(values), len(errors))
        return {"values": values, "errors": errors}


def _error(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


# --------------------------------------------------------------------------
# Client (used by the broker)
# --------------------------------------------------------------------------


def fetch_values(
    socket_path: str, refs: list[str] | None = None, timeout: float = 90.0
) -> tuple[dict[str, str], list[str]]:
    """Ask the keeper for the decrypted value set.

    Returns ``(values, errors)``.  Raises :class:`KeeperError` if the keeper
    cannot be reached or refuses the request; a per-file decryption failure
    comes back in ``errors`` instead, so one broken file does not blank the
    whole value set.
    """
    request: dict[str, Any] = {"op": "get_values"}
    if refs is not None:
        request["refs"] = refs
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(socket_path)
    except OSError as exc:
        sock.close()
        raise KeeperError(
            f"keeper socket {socket_path}: {exc.strerror or exc}"
        ) from exc

    with sock:
        try:
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
        except OSError as exc:
            raise KeeperError(f"keeper: {exc.strerror or exc}") from exc

    if not chunks.strip():
        raise KeeperError("keeper closed the connection without responding")
    try:
        response = json.loads(chunks.split(b"\n", 1)[0].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeeperError(f"malformed response from keeper: {exc}") from exc

    if response.get("error"):
        err = response["error"]
        raise KeeperError(f"keeper: {err.get('code')}: {err.get('message')}")
    values = response.get("values")
    if not isinstance(values, dict):
        raise KeeperError("keeper response has no 'values' object")
    errors = response.get("errors")
    return (
        {str(k): str(v) for k, v in values.items()},
        [str(e) for e in errors] if isinstance(errors, list) else [],
    )


# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="faramir-keeper",
        description="holds the age key and serves decrypted values",
    )
    parser.add_argument("-c", "--config", default=None, help="path to config.toml")
    parser.add_argument("--check", action="store_true", help="decrypt once and exit")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        config = Config.load(args.config)
    except ConfigError as exc:
        log.error("%s", exc)
        return 2

    keeper = Keeper(config)

    if args.check:
        values, errors = decrypt_all(config.secrets, keeper.keys)
        # Names only.  Even the operator-facing check does not print values.
        print(json.dumps({"refs": sorted(values), "errors": errors}, indent=2))
        return 1 if errors else 0

    signal.signal(signal.SIGTERM, keeper.stop)
    signal.signal(signal.SIGINT, keeper.stop)

    keeper.listen()
    _notify_ready()
    keeper.serve_forever()
    return 0


def _notify_ready() -> None:
    """sd_notify(READY=1) so systemd knows the socket is being served."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(addr)
            sock.sendall(b"READY=1")
    except OSError as exc:
        log.debug("sd_notify failed: %s", exc)


if __name__ == "__main__":
    sys.exit(main())

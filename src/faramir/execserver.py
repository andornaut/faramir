"""Runs brokered commands as a uid that holds nothing.

The broker resolves policy, injects secret values, redacts output and writes
the audit log.  It does not fork the child: this service does, under
``faramir-exec``, which holds no secrets, cannot read the raw log, cannot read
the age key, and cannot write the execution checkout.

The split is what makes those statements true.  A child forked by the broker
shares the broker's uid, and anything that uid can read or write, the child can
read or write.

The PTY stays on the broker's side.  The broker creates the pair, sends the
*slave* over ``SCM_RIGHTS``, and keeps the master, so redaction, truncation and
the audit log run exactly where they always did and the output never makes an
extra hop.  This service does the fork, the session setup and the reaping, and
reports an exit status.

Protocol: one line of JSON plus one file descriptor in, one line of JSON out.

    -> {"argv": [...], "cwd": "...", "env": {...},
        "timeout_sec": 600, "kill_grace_sec": 5}   + pty slave fd
    <- {"exit_code": 0, "timed_out": false}
    <- {"error": {"code": ..., "message": ...}}

Closing the connection is how the broker says "give up": the child's process
group is killed.  That covers the broker dying mid-command, which would
otherwise leave an orphan holding a credential in its environment.
"""

from __future__ import annotations

import errno
import grp
import json
import logging
import os
import pwd
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any

from .config import Config, ConfigError, ExecConfig

log = logging.getLogger("faramir.exec")

_SO_PEERCRED = 17  # SO_PEERCRED on Linux
_UCRED = struct.Struct("3i")
_MAX_REQUEST_BYTES = 1048576
_POLL_SEC = 0.05


class ExecError(Exception):
    """The executor refused the request, or could not be reached."""


# --------------------------------------------------------------------------
# Child setup
# --------------------------------------------------------------------------


def _child_setup() -> None:
    """Runs in the forked child, before exec: become session and TTY leader.

    CPython performs the stdin/stdout/stderr dup2 before calling this, so fd 1
    is already the PTY slave.  fd 0 is not: stdin is /dev/null, so the
    controlling terminal has to be claimed through one of the other two.
    """
    os.setsid()
    try:
        import fcntl
        import termios

        fcntl.ioctl(1, termios.TIOCSCTTY, 0)
    except OSError:
        pass


def _terminate(proc: subprocess.Popen[bytes], grace_sec: int) -> None:
    """SIGTERM the whole process group, then SIGKILL what is left."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            try:
                proc.send_signal(sig)
            except ProcessLookupError:
                return
        try:
            proc.wait(timeout=grace_sec if sig == signal.SIGTERM else 5)
            return
        except subprocess.TimeoutExpired:
            log.warning("pid %d survived %s", proc.pid, sig.name)


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------


class Executor:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._stop = False
        self._listener: socket.socket | None = None
        self._slots = threading.BoundedSemaphore(config.executor.max_concurrency)

    # -- lifecycle ---------------------------------------------------------

    def listen(self) -> socket.socket:
        fds = int(os.environ.get("LISTEN_FDS", "0") or 0)
        listen_pid = int(os.environ.get("LISTEN_PID", "0") or 0)
        if fds and listen_pid == os.getpid():
            if fds != 1:
                raise SystemExit(f"expected exactly 1 socket from systemd, got {fds}")
            sock = socket.socket(fileno=3)  # SD_LISTEN_FDS_START
            sock.setblocking(True)
            log.info("using socket activation fd 3")
        else:
            path = self.config.executor.socket_path
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.exists(path):
                os.unlink(path)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            previous = os.umask(0o777 ^ self.config.executor.socket_mode)
            try:
                sock.bind(path)
            finally:
                os.umask(previous)
            os.chmod(path, self.config.executor.socket_mode)
            sock.listen(16)
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
            threading.Thread(
                target=self._serve_connection, args=(conn,), daemon=True
            ).start()
        log.info("shutting down")

    def stop(self, *_: Any) -> None:
        self._stop = True

    # -- connection handling ----------------------------------------------

    def _serve_connection(self, conn: socket.socket) -> None:
        slave_fd: int | None = None
        try:
            if not self._peer_allowed(conn):
                self._send(conn, _error("forbidden", "peer not authorized"))
                return
            payload, slave_fd = self._read_request(conn)
            if payload is None:
                self._send(conn, _error("bad_request", "no usable request"))
                return
            if slave_fd is None:
                self._send(conn, _error("bad_request", "no terminal fd was passed"))
                return
            if not self._slots.acquire(blocking=False):
                self._send(conn, _error("busy", "executor is at its concurrency limit"))
                return
            try:
                self._send(conn, self.run(payload, slave_fd, conn))
            finally:
                self._slots.release()
        except Exception as exc:  # noqa: BLE001 - one bad connection must not kill us
            log.exception("connection failed")
            try:
                self._send(conn, _error("internal", str(exc)))
            except OSError:
                pass
        finally:
            if slave_fd is not None:
                try:
                    os.close(slave_fd)
                except OSError:
                    pass
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
        if uid in (0, os.getuid()):
            return True
        for name in self.config.executor.allowed_users:
            try:
                if pwd.getpwnam(name).pw_uid == uid:
                    return True
            except KeyError:
                continue
        for name in self.config.executor.allowed_groups:
            try:
                entry = grp.getgrnam(name)
            except KeyError:
                continue
            if gid == entry.gr_gid:
                return True
        log.warning("rejected connection from uid=%d gid=%d pid=%d", uid, gid, pid)
        return False

    @staticmethod
    def _read_request(conn: socket.socket) -> tuple[Any, int | None]:
        """Read one JSON line and the single fd that accompanies it."""
        buf = bytearray()
        fds: list[int] = []
        conn.settimeout(30.0)
        while b"\n" not in buf:
            try:
                chunk, ancillary, _flags, _addr = socket.recv_fds(conn, 65536, 1)
            except socket.timeout:
                break
            fds.extend(ancillary)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > _MAX_REQUEST_BYTES:
                break
        # Any fd past the first is a caller bug; close them rather than leak.
        for extra in fds[1:]:
            try:
                os.close(extra)
            except OSError:
                pass
        slave_fd = fds[0] if fds else None
        if not buf.strip():
            return None, slave_fd
        try:
            return json.loads(buf.split(b"\n", 1)[0].decode("utf-8")), slave_fd
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, slave_fd

    @staticmethod
    def _send(conn: socket.socket, response: dict[str, Any]) -> None:
        try:
            conn.sendall(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
        except OSError:
            pass  # the broker gave up; the child has already been dealt with

    # -- execution ---------------------------------------------------------

    def run(self, payload: Any, slave_fd: int, conn: socket.socket) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return _error("bad_request", "request must be a JSON object")
        argv = payload.get("argv")
        if not isinstance(argv, list) or not argv or not all(
            isinstance(a, str) for a in argv
        ):
            return _error("bad_request", "'argv' must be a non-empty list of strings")
        env = payload.get("env") or {}
        if not isinstance(env, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in env.items()
        ):
            return _error("bad_request", "'env' must be a map of strings to strings")
        cwd = payload.get("cwd") or self.config.exec.default_cwd
        if not isinstance(cwd, str):
            return _error("bad_request", "'cwd' must be a string")

        reason = _outside_bin_dirs(argv[0], self.config.exec)
        if reason:
            # The broker checks this too.  Repeating it here means a broker bug
            # cannot turn into "run anything from anywhere as faramir-exec".
            return _error("denied", reason)

        env = dict(env)
        # The child's HOME belongs to *this* uid, not the broker's.  Ansible
        # creates ~/.ansible/tmp unconditionally and fails if it cannot.
        env.setdefault("HOME", _own_home())

        timeout_sec = _positive(payload.get("timeout_sec"), self.config.exec.default_timeout_sec)
        grace_sec = _positive(payload.get("kill_grace_sec"), self.config.exec.kill_grace_sec)

        started = time.monotonic()
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv is allowlisted by the broker
                argv,
                cwd=cwd,
                env=env,
                # Nothing ever writes to the master, so a child reading stdin
                # would block until its timeout, holding a concurrency slot:
                # `bash` with no arguments, or any password prompt, does it.
                # /dev/null turns that into an immediate EOF.  stdout and
                # stderr keep the PTY, which is what `test -t 1` and writes to
                # /dev/tty depend on.
                stdin=subprocess.DEVNULL,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                preexec_fn=_child_setup,  # noqa: PLW1509
            )
        except OSError as exc:
            return _error("exec_failed", f"{argv[0]}: {exc}")
        # The broker holds the master; our copy of the slave must go, or the
        # master never reaches EOF and the broker waits forever.
        try:
            os.close(slave_fd)
        except OSError:
            pass

        timed_out = self._await(proc, conn, started + timeout_sec, grace_sec, timeout_sec)
        exit_code = proc.wait()
        if exit_code < 0:
            exit_code = 128 - exit_code  # 128 + signal number
        log.info(
            "%s exit=%s dur=%.1fs%s",
            os.path.basename(argv[0]),
            exit_code,
            time.monotonic() - started,
            " (timed out)" if timed_out else "",
        )
        return {
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_sec": round(time.monotonic() - started, 3),
        }

    def _await(
        self,
        proc: subprocess.Popen[bytes],
        conn: socket.socket,
        deadline: float,
        grace_sec: int,
        timeout_sec: int,
    ) -> bool:
        """Wait for the child, watching the clock and the broker's connection."""
        while True:
            if proc.poll() is not None:
                return False
            if time.monotonic() >= deadline:
                log.warning("pid %d exceeded %ds; killing", proc.pid, timeout_sec)
                _terminate(proc, grace_sec)
                return True
            # A readable connection means the broker sent something (it should
            # not) or hung up.  Either way it is no longer waiting for us, and
            # an orphan holding a credential in its environment is exactly what
            # must not survive.
            try:
                ready, _, _ = select.select([conn], [], [], _POLL_SEC)
            except (OSError, ValueError):
                _terminate(proc, grace_sec)
                return False
            if ready:
                try:
                    if conn.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT):
                        continue  # unexpected data; keep going
                except BlockingIOError:
                    continue
                except OSError:
                    pass
                log.warning("broker hung up; killing pid %d", proc.pid)
                _terminate(proc, grace_sec)
                return False


def _own_home() -> str:
    try:
        return pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        return "/tmp"


def _positive(value: Any, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else default


def _outside_bin_dirs(argv0: str, exec_cfg: ExecConfig) -> str | None:
    resolved = os.path.realpath(argv0)
    directory = os.path.dirname(resolved)
    if any(
        directory == d or directory.startswith(d.rstrip("/") + "/")
        for d in exec_cfg.allowed_bin_dirs
    ):
        return None
    return f"{argv0}: resolves to {resolved}, which is outside allowed_bin_dirs"


def _error(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


# --------------------------------------------------------------------------
# Client (used by the broker)
# --------------------------------------------------------------------------


class ChildResult:
    def __init__(self, exit_code: int, timed_out: bool) -> None:
        self.exit_code = exit_code
        self.timed_out = timed_out


class ExecClient:
    """One brokered command: start it, then collect its exit status.

    The broker keeps the PTY master and reads it between :meth:`start` and
    :meth:`result`, so this cannot be a single blocking call.
    """

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self._sock: socket.socket | None = None

    def start(
        self,
        argv: list[str],
        cwd: str,
        env: dict[str, str],
        timeout_sec: int,
        kill_grace_sec: int,
        slave_fd: int,
    ) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(30.0)
            sock.connect(self.socket_path)
        except OSError as exc:
            sock.close()
            raise ExecError(
                f"executor socket {self.socket_path}: {exc.strerror or exc}"
            ) from exc
        self._sock = sock
        request = {
            "argv": list(argv),
            "cwd": cwd,
            "env": dict(env),
            "timeout_sec": timeout_sec,
            "kill_grace_sec": kill_grace_sec,
        }
        line = json.dumps(request).encode("utf-8") + b"\n"
        try:
            socket.send_fds(sock, [line], [slave_fd])
        except OSError as exc:
            self.close()
            raise ExecError(f"executor: {exc.strerror or exc}") from exc

    def abort(self) -> None:
        """Hang up.  The executor kills the child's process group."""
        self.close()

    def result(self, timeout: float = 30.0) -> ChildResult:
        sock = self._sock
        if sock is None:
            raise ExecError("executor: no command in flight")
        sock.settimeout(timeout)
        chunks = bytearray()
        try:
            while b"\n" not in chunks:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.extend(data)
        except OSError as exc:
            raise ExecError(f"executor: {exc.strerror or exc}") from exc
        finally:
            self.close()

        if not chunks.strip():
            raise ExecError("executor closed the connection without responding")
        try:
            response = json.loads(chunks.split(b"\n", 1)[0].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecError(f"malformed response from executor: {exc}") from exc
        if response.get("error"):
            err = response["error"]
            raise ExecError(f"{err.get('code')}: {err.get('message')}")
        code = response.get("exit_code")
        if not isinstance(code, int):
            raise ExecError("executor response has no exit_code")
        return ChildResult(code, bool(response.get("timed_out")))

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="faramir-exec", description="runs brokered commands, holds no secrets"
    )
    parser.add_argument("-c", "--config", default=None, help="path to config.toml")
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

    executor = Executor(config)
    signal.signal(signal.SIGTERM, executor.stop)
    signal.signal(signal.SIGINT, executor.stop)

    executor.listen()
    _notify_ready()
    executor.serve_forever()
    return 0


def _notify_ready() -> None:
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

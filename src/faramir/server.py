"""The broker daemon.

Socket-activated by systemd (``LISTEN_FDS``); falls back to binding the socket
itself when run standalone, which is how the test harness drives it.

Concurrency is bounded (``[server] max_concurrency``) because each brokered
command may be a full Ansible run.  Requests over the limit are refused with a
clear error rather than queued indefinitely.
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
import sys
import threading
import time
from typing import Any

from . import __version__
from .audit import AuditLog, RawCollector, new_log_id
from .config import Config, ConfigError
from .execserver import ExecError
from .executor import run as exec_run
from .protocol import ProtocolError, Request, error_response, resolve_inline_tokens
from .redact import Redactor
from .resolve import ResolveError, resolve_program
from .secretstore import SecretError, SecretStore, parse_secret_uri
from .sshagent import SshAgent

log = logging.getLogger("faramir")

_SO_PEERCRED = 17  # SO_PEERCRED on Linux
_UCRED = struct.Struct("3i")


class Server:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.store = SecretStore(config.secrets, config.keeper)
        self.audit = AuditLog(config.audit)
        self.ssh = SshAgent(config.ssh)
        self._slots = threading.BoundedSemaphore(config.server.max_concurrency)
        self._stop = threading.Event()
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
            path = self.config.server.socket_path
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.exists(path):
                os.unlink(path)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            previous = os.umask(0o777 ^ self.config.server.socket_mode)
            try:
                sock.bind(path)
            finally:
                os.umask(previous)
            os.chmod(path, self.config.server.socket_mode)
            sock.listen(16)
            log.info("listening on %s", path)
        self._listener = sock
        return sock

    def serve_forever(self) -> None:
        sock = self._listener or self.listen()
        sock.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                if self._stop.is_set():
                    break
                raise
            threading.Thread(
                target=self._serve_connection, args=(conn,), daemon=True
            ).start()
        log.info("shutting down")

    def stop(self, *_: Any) -> None:
        self._stop.set()

    def reload(self, *_: Any) -> None:
        log.info("SIGHUP: reloading secrets")
        try:
            self.store.reload()
        except Exception as exc:  # noqa: BLE001 - a reload failure must not kill the daemon
            log.error("reload failed: %s", exc)

    # -- connection handling ----------------------------------------------

    def _serve_connection(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(30.0)
            peer = self._peer(conn)
            if peer is None:
                self._send(conn, error_response("forbidden", "peer not authorized"))
                return
            payload = self._read_request(conn)
            if payload is None:
                return
            conn.settimeout(None)
            response = self.handle(payload, peer)
            self._send(conn, response)
        except Exception as exc:  # noqa: BLE001 - one bad connection must not kill us
            log.exception("connection failed")
            try:
                self._send(conn, error_response("internal", self._safe_detail(exc)))
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _safe_detail(self, exc: BaseException) -> str:
        """An exception message the agent may see.

        An unexpected exception can have interpolated a secret into its message,
        so it goes through the redactor like every other agent-visible string.
        If building the redactor is what failed, say nothing rather than risk it.
        """
        try:
            return Redactor(self.store.pairs(), self.store.policy).redact_text(str(exc))
        except Exception:  # noqa: BLE001 - the error path must not raise
            log.exception("could not redact error detail")
            return "internal error (see the broker log)"

    def _peer(self, conn: socket.socket) -> dict[str, Any] | None:
        """SO_PEERCRED check.

        The socket mode already restricts this to the ``devwork`` group; this
        is belt and braces, and it gives the audit log a real uid.
        """
        try:
            raw = conn.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, _UCRED.size)
            pid, uid, gid = _UCRED.unpack(raw)
        except OSError as exc:
            log.warning("SO_PEERCRED unavailable: %s", exc)
            return None
        cfg = self.config.server
        allowed = uid == 0 or uid == os.getuid()
        if not allowed and cfg.allowed_uids:
            allowed = uid in cfg.allowed_uids
        if not allowed and cfg.allowed_groups:
            try:
                name = pwd.getpwuid(uid).pw_name
            except KeyError:
                name = None
            for group in cfg.allowed_groups:
                try:
                    entry = grp.getgrnam(group)
                except KeyError:
                    continue
                if gid == entry.gr_gid or (name and name in entry.gr_mem):
                    allowed = True
                    break
        if not allowed:
            log.warning("rejected connection from uid=%d gid=%d pid=%d", uid, gid, pid)
            return None
        return {"pid": pid, "uid": uid, "gid": gid}

    def _read_request(self, conn: socket.socket) -> Any:
        limit = self.config.server.max_request_bytes
        buf = bytearray()
        while b"\n" not in buf:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                self._send(conn, error_response("timeout", "no request received"))
                return None
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > limit:
                self._send(
                    conn, error_response("too_large", f"request exceeds {limit} bytes")
                )
                return None
        if not buf.strip():
            return None
        try:
            return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send(conn, error_response("bad_request", f"invalid JSON: {exc}"))
            return None

    @staticmethod
    def _send(conn: socket.socket, response: dict[str, Any]) -> None:
        data = json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
        conn.sendall(data)

    # -- dispatch ----------------------------------------------------------

    def handle(self, payload: Any, peer: dict[str, Any]) -> dict[str, Any]:
        try:
            request = Request.parse(payload)
        except ProtocolError as exc:
            return error_response("bad_request", str(exc))

        self.store.refresh_if_stale()

        if request.op == "status":
            return self._op_status()
        if request.op == "list_secrets":
            return self._op_list_secrets()
        return self._op_exec(request, peer)

    def _op_status(self) -> dict[str, Any]:
        return {
            "exit_code": 0,
            "output": json.dumps(
                {
                    "version": __version__,
                    "config": self.config.path,
                    "secrets": self.store.describe(),
                    "default_cwd": self.config.exec.default_cwd,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            "truncated": False,
            "redactions": [],
            "log_id": None,
        }

    def _op_list_secrets(self) -> dict[str, Any]:
        # Names only, and only refs that were actually loaded: a value the
        # redactor cannot cover is refused at load and never listed here.
        refs = self.store.refs()
        return {
            "exit_code": 0,
            "output": "".join(f"secret://{ref}\n" for ref in refs),
            "truncated": False,
            "redactions": [],
            "log_id": None,
            "refs": refs,
        }

    def _op_exec(self, request: Request, peer: dict[str, Any]) -> dict[str, Any]:
        exec_cfg = self.config.exec
        log_id = new_log_id()

        try:
            cmd, env_refs = resolve_inline_tokens(request.cmd, request.env_refs)
        except SecretError as exc:
            return error_response("bad_request", str(exc), log_id)

        cwd = request.cwd or exec_cfg.default_cwd
        if not os.path.isdir(cwd):
            return error_response("bad_request", f"cwd does not exist: {cwd}", log_id)

        try:
            argv0_path = resolve_program(cmd[0], cwd, exec_cfg)
        except ResolveError as exc:
            self.audit.write(
                {
                    "log_id": log_id,
                    "op": "exec",
                    "peer": peer,
                    "cmd": cmd,
                    "cwd": cwd,
                    "error": str(exc),
                },
                "",
            )
            return error_response("exec_failed", str(exc), log_id)

        # Resolve secret values.  This is the only place plaintext is touched
        # outside the store, and it goes straight into the child's environ.
        # The age key is not among them: the keeper holds it, and nothing the
        # broker executes can obtain it.
        # HOME is left to the executor: the child runs as its uid, not ours.
        env = dict(exec_cfg.base_env)
        # SSH_AUTH_SOCK, when the broker holds the keys in an agent.  The
        # child can authenticate with them; it cannot read them.
        env.update(self.ssh.env())
        injected: dict[str, str] = {}
        for name, uri in env_refs.items():
            try:
                ref = parse_secret_uri(uri)
                env[name] = self.store.value(ref)
                injected[name] = ref
            except SecretError as exc:
                return error_response("unknown_secret", str(exc), log_id)

        timeout = min(
            request.timeout_sec or exec_cfg.default_timeout_sec, exec_cfg.max_timeout_sec
        )

        if not self._slots.acquire(blocking=False):
            return error_response(
                "busy",
                f"broker is at its concurrency limit "
                f"({self.config.server.max_concurrency}); retry shortly",
                log_id,
            )

        # The value set is *every* known secret, not only the injected ones: a
        # managed host can print a credential the broker never injected, and
        # catching that is the accidental-disclosure guarantee.
        redactor = Redactor(self.store.pairs(), self.store.policy)
        collector = RawCollector(self.config.audit.max_record_bytes)
        started = time.time()
        try:
            result = exec_run(
                [argv0_path, *cmd[1:]],
                cwd=cwd,
                env=env,
                timeout_sec=timeout,
                redactor=redactor,
                exec_cfg=exec_cfg,
                executor_cfg=self.config.executor,
                raw_sink=collector,
            )
        except ExecError as exc:
            return error_response("exec_failed", str(exc), log_id)
        except OSError as exc:
            return error_response("exec_failed", f"{cmd[0]}: {exc}", log_id)
        finally:
            self._slots.release()
            env.clear()

        self.audit.write(
            {
                "log_id": log_id,
                "op": "exec",
                "peer": peer,
                "cmd": cmd,
                "argv0_path": argv0_path,
                "cwd": cwd,
                "env_refs": injected,
                "exit_code": result.exit_code,
                "duration_sec": result.duration_sec,
                "timed_out": result.timed_out,
                "started_at": started,
                "redactions": result.redactions,
            },
            collector.text(),
        )
        log.info(
            "%s %s exit=%s dur=%.1fs redactions=%d",
            log_id,
            os.path.basename(argv0_path),
            result.exit_code,
            result.duration_sec,
            sum(int(r["count"]) for r in result.redactions),  # type: ignore[arg-type]
        )
        return {
            "exit_code": result.exit_code,
            "output": result.output,
            "truncated": result.truncated,
            "redactions": result.redactions,
            "log_id": log_id,
            "timed_out": result.timed_out,
            "duration_sec": result.duration_sec,
        }

def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="faramir-broker", description="secret broker daemon"
    )
    parser.add_argument("-c", "--config", default=None, help="path to config.toml")
    parser.add_argument("--check", action="store_true", help="validate config and exit")
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

    server = Server(config)
    server.store.reload()

    # Before starting the agent: --check runs against a live broker, and
    # starting a second agent would replace the running one's socket and
    # outlive this process with the fleet keys loaded.
    if args.check:
        # One JSON object, shaped like the status op, but operator-facing:
        # this one names the refs that were refused at load.
        secrets = server.store.describe_for_operator()
        print(
            json.dumps(
                {"secrets": secrets},
                indent=2,
                sort_keys=True,
            )
        )
        # Non-zero on a refused ref: the config parses, but a command that
        # injects that ref will fail at runtime, and --check is the install
        # gate that is supposed to catch it (install/20-install-broker.sh).
        refused = secrets["not_redactable"]
        if refused:
            log.error(
                "%d secret(s) refused as not redactable: %s",
                len(refused),
                ", ".join(refused),
            )
            return 1
        return 0

    server.ssh.start()
    try:
        signal.signal(signal.SIGHUP, server.reload)
        signal.signal(signal.SIGTERM, server.stop)
        signal.signal(signal.SIGINT, server.stop)

        server.listen()
        notify_ready()
        server.serve_forever()
    finally:
        # Covers listen() too: a failed bind must not leave an agent holding
        # the fleet keys on a socket the executor's group can already reach.
        server.ssh.stop()
    return 0


def notify_ready() -> None:
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

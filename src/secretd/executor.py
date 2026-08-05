"""Runs the child on a PTY and streams its output through the redactor.

Why a PTY and not a pipe:

1. Programs behave normally when stdout is a terminal -- colour, progress
   meters, line buffering.  Ansible in particular formats very differently.
2. A process can write straight to ``/dev/tty``, bypassing stdout redirection
   entirely; ``ssh`` and ``sudo`` do exactly this for password prompts.  Owning
   the controlling terminal catches those writes.  A pipe does not.

The consequence is that stdout and stderr arrive merged.  That is accepted.
"""

from __future__ import annotations

import codecs
import errno
import fcntl
import logging
import os
import pty
import select
import signal
import struct
import subprocess
import termios
import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

from .config import ExecConfig
from .redact import Redactor

log = logging.getLogger("secretd.exec")

_READ_SIZE = 65536


@dataclass
class ExecResult:
    exit_code: int
    output: str
    truncated: bool
    duration_sec: float
    timed_out: bool = False
    redactions: list[dict[str, object]] = field(default_factory=list)


def _child_setup() -> None:
    """Runs in the forked child, before exec: become session and TTY leader."""
    os.setsid()
    try:
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    except OSError:
        pass


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except OSError:
        pass


def run(
    argv: Sequence[str],
    cwd: str,
    env: dict[str, str],
    timeout_sec: int,
    redactor: Redactor,
    exec_cfg: ExecConfig,
    raw_sink: Callable[[str], None] | None = None,
) -> ExecResult:
    """Execute ``argv``, returning redacted merged output.

    ``raw_sink`` receives the *unredacted* text for the operator-only audit
    log.  Nothing else in this process ever sees it.
    """
    master, slave = pty.openpty()
    _set_winsize(master, exec_cfg.term_rows, exec_cfg.term_cols)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv is allowlisted, never a shell string
            list(argv),
            cwd=cwd,
            env=env,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
            preexec_fn=_child_setup,  # noqa: PLW1509 - single-threaded fork, no locks held
        )
    except OSError:
        os.close(master)
        raise
    finally:
        try:
            os.close(slave)
        except OSError:
            pass

    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    chunks: list[str] = []
    emitted = 0
    truncated = False
    timed_out = False
    deadline = started + timeout_sec

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate(proc, exec_cfg.kill_grace_sec)
                break
            try:
                ready, _, _ = select.select([master], [], [], min(remaining, 1.0))
            except InterruptedError:
                continue
            if not ready:
                continue
            try:
                data = os.read(master, _READ_SIZE)
            except OSError as exc:
                if exc.errno in (errno.EIO, errno.EBADF):
                    break  # child closed the slave side: normal EOF on a PTY
                raise
            if not data:
                break
            text = decoder.decode(data)
            if not text:
                continue
            if raw_sink is not None:
                raw_sink(text)
            safe = redactor.feed(text)
            if safe:
                emitted, truncated = _append(
                    chunks, safe, emitted, exec_cfg.max_output_bytes, truncated
                )
    finally:
        tail = decoder.decode(b"", final=True)
        if tail and raw_sink is not None:
            raw_sink(tail)
        if tail:
            redactor.feed(tail)
        final = redactor.flush()
        if final:
            emitted, truncated = _append(
                chunks, final, emitted, exec_cfg.max_output_bytes, truncated
            )
        try:
            os.close(master)
        except OSError:
            pass

    exit_code = proc.wait()
    if exit_code < 0:
        exit_code = 128 - exit_code  # 128 + signal number
    if timed_out:
        chunks.append(f"\n[secretd] timed out after {timeout_sec}s; process killed\n")

    return ExecResult(
        exit_code=exit_code,
        output="".join(chunks),
        truncated=truncated,
        duration_sec=round(time.monotonic() - started, 3),
        timed_out=timed_out,
        redactions=redactor.summary(),
    )


def _append(
    chunks: list[str], text: str, emitted: int, limit: int, truncated: bool
) -> tuple[int, bool]:
    """Append output up to ``limit`` bytes; keep draining the PTY after that.

    Draining matters: if we stopped reading, a chatty child would block on a
    full PTY buffer and never exit.
    """
    if truncated:
        return emitted, True
    size = len(text.encode("utf-8", "replace"))
    if emitted + size <= limit:
        chunks.append(text)
        return emitted + size, False
    room = max(0, limit - emitted)
    if room:
        chunks.append(text.encode("utf-8", "replace")[:room].decode("utf-8", "ignore"))
    chunks.append(f"\n[secretd] output truncated at {limit} bytes\n")
    return limit, True


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

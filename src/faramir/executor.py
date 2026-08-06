"""Owns the PTY, and streams the child's output through the redactor.

Why a PTY and not a pipe:

1. Programs behave normally when stdout is a terminal -- colour, progress
   meters, line buffering.  Ansible in particular formats very differently.
2. A process can write straight to ``/dev/tty``, bypassing stdout redirection
   entirely; ``ssh`` and ``sudo`` do exactly this for password prompts.  Owning
   the controlling terminal catches those writes.  A pipe does not.

The consequence is that stdout and stderr arrive merged.  That is accepted.

The fork happens in ``faramir-exec``, under a uid that holds nothing, but the
PTY does not move with it: the broker creates the pair, hands the *slave* over
``SCM_RIGHTS`` and keeps the master.  Redaction, truncation and the audit log
therefore stay on this side, reading the child's bytes directly, with no extra
hop for output to take.
"""

from __future__ import annotations

import codecs
import errno
import fcntl
import logging
import os
import pty
import select
import struct
import termios
import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

from .config import ExecConfig, ExecutorConfig
from .execserver import ExecClient, ExecError
from .redact import Redactor

log = logging.getLogger("faramir.exec")

_READ_SIZE = 65536
# How long past the executor's own kill deadline we wait before giving up on it.
_BACKSTOP_MARGIN_SEC = 10


@dataclass
class ExecResult:
    exit_code: int
    output: str
    truncated: bool
    duration_sec: float
    timed_out: bool = False
    redactions: list[dict[str, object]] = field(default_factory=list)


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
    executor_cfg: ExecutorConfig,
    raw_sink: Callable[[str], None] | None = None,
) -> ExecResult:
    """Execute ``argv`` through the executor, returning redacted merged output.

    ``raw_sink`` receives the *unredacted* text for the operator-only audit
    log.  Nothing else in this process ever sees it.
    """
    master, slave = pty.openpty()
    _set_winsize(master, exec_cfg.term_rows, exec_cfg.term_cols)
    started = time.monotonic()
    client = ExecClient(executor_cfg.socket_path)
    try:
        client.start(
            argv=list(argv),
            cwd=cwd,
            env=env,
            timeout_sec=timeout_sec,
            kill_grace_sec=exec_cfg.kill_grace_sec,
            slave_fd=slave,
        )
    except ExecError:
        os.close(master)
        raise
    finally:
        # The executor has its own copy now.  Ours has to go, or the master
        # never reaches EOF when the child exits.
        try:
            os.close(slave)
        except OSError:
            pass

    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    chunks: list[str] = []
    emitted = 0
    truncated = False
    aborted = False
    # The executor enforces the timeout, because it owns the process group.
    # This is a backstop for the case where it does not come back at all.
    deadline = started + timeout_sec + exec_cfg.kill_grace_sec + _BACKSTOP_MARGIN_SEC

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                aborted = True
                client.abort()  # hanging up kills the child's process group
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

    if aborted:
        exit_code, timed_out = 128 + 9, True
    else:
        result = client.result()
        exit_code, timed_out = result.exit_code, result.timed_out
    if timed_out:
        chunks.append(f"\n[faramir] timed out after {timeout_sec}s; process killed\n")

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
    chunks.append(f"\n[faramir] output truncated at {limit} bytes\n")
    return limit, True

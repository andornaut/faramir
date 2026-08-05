"""Unredacted audit log, readable only by the broker's uid.

The operator needs the real output to debug a failed playbook; the agent must
not be able to read it.  The response carries a ``log_id`` that points into
this file, which is the whole point: the agent can say "see log
2026-08-05T14:22:01Z-a91f" without seeing what is in it.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import AuditConfig

log = logging.getLogger("secretd.audit")


def new_log_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{stamp}-{secrets.token_hex(2)}"


class AuditLog:
    """Append-only JSONL sink.  One record per brokered invocation."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._ready = False

    def _ensure(self) -> None:
        if self._ready:
            return
        path = Path(self.config.raw_log)
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # os.open with an explicit mode rather than umask-plus-touch: the
            # umask is process-wide, and a child forked by another request
            # thread during that window would inherit it and create files the
            # devwork group cannot read.
            os.close(os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600))
            os.chmod(path, 0o600)
            self._ready = True
        except OSError as exc:
            log.error("cannot open audit log %s: %s", path, exc)
            raise

    def write(self, record: dict[str, Any], raw_output: str) -> None:
        """Record one invocation together with its *unredacted* output."""
        payload = dict(record)
        limit = self.config.max_record_bytes
        encoded = raw_output.encode("utf-8", "replace")
        if len(encoded) > limit:
            payload["raw_truncated"] = True
            raw_output = encoded[:limit].decode("utf-8", "ignore")
        payload["raw_output"] = raw_output
        line = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self._lock:
            try:
                self._ensure()
                with open(self.config.raw_log, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:  # never fail a request because logging broke
                log.error("audit write failed: %s", exc)


class RawCollector:
    """Accumulates the unredacted stream for one invocation, with a hard cap."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._parts: list[str] = []
        self._size = 0

    def __call__(self, text: str) -> None:
        if self._size >= self.limit:
            return
        self._parts.append(text)
        self._size += len(text)

    def text(self) -> str:
        return "".join(self._parts)

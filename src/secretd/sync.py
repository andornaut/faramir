"""Mediated promotion of the agent's working tree into the broker's checkout.

Without this, isolation buys very little.  The agent can write

    - name: oops
      debug: var=vault_router_password

into a playbook and ask the broker to run it -- an authorized action that no
amount of uid separation prevents.  Redaction still catches the value, but the
broker should not be executing whatever happens to be in the agent's editor
buffer.  So: the agent authors and commits; ``sync`` fetches that commit into
``/srv``; the broker only ever executes committed content.

``sync`` is a separate op with its own allowlist (``[sync] allowed_refs``) --
it is deliberately not reachable through the generic exec path.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Sequence

from .config import SyncConfig

log = logging.getLogger("secretd.sync")


class SyncError(Exception):
    """Sync refused or failed."""


@dataclass
class SyncResult:
    commit: str
    subject: str
    output: str


def _git(cfg: SyncConfig, args: Sequence[str], cwd: str | None = None) -> str:
    argv = [cfg.git, *args]
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": os.environ.get("HOME", "/tmp"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
        "GIT_CONFIG_NOSYSTEM": "1",
        "LANG": "C.UTF-8",
        # The source tree is owned by the agent's uid and read by the broker's,
        # which git refuses as "dubious ownership" since 2.35.2.  Grant it for
        # exactly the two paths sync touches, via the environment rather than a
        # config file: nothing the agent can write changes what this trusts.
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": cfg.source,
        "GIT_CONFIG_KEY_1": "safe.directory",
        "GIT_CONFIG_VALUE_1": cfg.dest,
    }
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=cfg.timeout_sec,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SyncError(f"git {' '.join(args)}: {exc}") from exc
    out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    if proc.returncode != 0:
        raise SyncError(f"git {' '.join(args)} failed ({proc.returncode}): {out.strip()}")
    return out


def sync(cfg: SyncConfig, ref: str | None) -> SyncResult:
    """Fetch ``ref`` from the agent's tree and hard-check it out in ``dest``."""
    if not cfg.enabled:
        raise SyncError("sync is disabled in the broker configuration")
    ref = (ref or cfg.default_ref).strip()
    if not cfg.allowed_refs:
        raise SyncError("sync: no allowed_refs configured, refusing")
    if not any(p.search(ref) for p in cfg.allowed_refs):
        raise SyncError(f"sync: ref {ref!r} is not permitted")
    if ref.startswith("-"):
        raise SyncError("sync: ref may not start with '-'")
    if not os.path.isdir(os.path.join(cfg.dest, ".git")):
        raise SyncError(f"sync: {cfg.dest} is not a git checkout")
    if not os.path.isdir(cfg.source):
        raise SyncError(f"sync: source {cfg.source} does not exist")

    transcript: list[str] = []
    transcript.append(_git(cfg, ["fetch", "--no-tags", "--", cfg.source, ref], cfg.dest))
    transcript.append(_git(cfg, ["checkout", "--force", "--detach", "FETCH_HEAD"], cfg.dest))
    if cfg.clean:
        transcript.append(_git(cfg, ["clean", "-xdff"], cfg.dest))
    commit = _git(cfg, ["rev-parse", "HEAD"], cfg.dest).strip()
    subject = _git(cfg, ["log", "-1", "--pretty=%s"], cfg.dest).strip()
    log.info("synced %s -> %s (%s)", cfg.source, commit[:12], subject)
    return SyncResult(commit=commit, subject=subject, output="".join(transcript))

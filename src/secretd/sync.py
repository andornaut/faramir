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

import contextlib
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Iterator, Sequence

from .config import SyncConfig

log = logging.getLogger("secretd.sync")


class SyncError(Exception):
    """Sync refused or failed."""


@dataclass
class SyncResult:
    commit: str
    subject: str
    output: str


def _config_quote(value: str) -> str:
    """Quote a path for a git-config value.

    Unquoted values stop at ``#`` or ``;``, lose trailing whitespace, and treat
    backslash as an escape, so a path containing any of those would produce a
    grant for some shorter path and the real one would still be refused.
    """
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


@contextlib.contextmanager
def _safe_directory_config(cfg: SyncConfig) -> Iterator[str]:
    """A throwaway git config granting ``safe.directory`` for sync's two repos.

    The source tree is owned by the agent's uid and read by the broker's, which
    git refuses as "dubious ownership" since 2.35.2.

    It has to be a file.  ``GIT_CONFIG_COUNT`` is part of git's
    ``local_repo_env``, so git strips it when it spawns ``upload-pack`` for the
    local-path fetch, and the grant never reaches the process that checks the
    source.  ``GIT_CONFIG_GLOBAL`` survives that hand-off.

    Both the worktree and its ``.git`` are listed: the child reports the path
    with the suffix, and a worktree-only entry does not satisfy it.

    Writing our own file also means the broker's real ``~/.gitconfig`` is
    ignored for these commands, which is what we want -- combined with
    ``GIT_CONFIG_NOSYSTEM``, sync reads no configuration it did not write.
    """
    entries = []
    for path in (cfg.source, cfg.dest):
        entries.append(path)
        entries.append(os.path.join(path, ".git"))
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="secretd-sync-", suffix=".gitconfig"
    ) as fh:
        fh.write("[safe]\n")
        for entry in entries:
            fh.write(f"\tdirectory = {_config_quote(entry)}\n")
        fh.flush()
        yield fh.name


def _git(
    cfg: SyncConfig,
    args: Sequence[str],
    cwd: str | None = None,
    config_file: str | None = None,
) -> str:
    argv = [cfg.git, *args]
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": os.environ.get("HOME", "/tmp"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
        "GIT_CONFIG_NOSYSTEM": "1",
        "LANG": "C.UTF-8",
    }
    if config_file:
        env["GIT_CONFIG_GLOBAL"] = config_file
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
    with _safe_directory_config(cfg) as gitconfig:
        transcript.append(
            _git(cfg, ["fetch", "--no-tags", "--", cfg.source, ref], cfg.dest, gitconfig)
        )
        transcript.append(
            _git(cfg, ["checkout", "--force", "--detach", "FETCH_HEAD"], cfg.dest, gitconfig)
        )
        if cfg.clean:
            transcript.append(_git(cfg, ["clean", "-xdff"], cfg.dest, gitconfig))
        commit = _git(cfg, ["rev-parse", "HEAD"], cfg.dest, gitconfig).strip()
        subject = _git(cfg, ["log", "-1", "--pretty=%s"], cfg.dest, gitconfig).strip()
    log.info("synced %s -> %s (%s)", cfg.source, commit[:12], subject)
    return SyncResult(commit=commit, subject=subject, output="".join(transcript))

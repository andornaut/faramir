"""The broker's view of the secret values, fetched from the keeper.

Two things matter here:

1. The value set is *every* secret the keeper knows about, not just the ones
   injected into the current command.  A secret can reach the output without
   having been injected -- a managed host printing its own configuration will
   do it -- and catching that is the accidental-disclosure guarantee.  So the
   broker holds the lot, and the redactor is built from all of it.
2. The broker never holds the age key.  It cannot decrypt anything; it asks
   the keeper, which runs as its own uid and serves values only.  Plaintext
   values live in this process's heap, are never written to disk, and are
   never placed in an argv.

The keeper is a separate process, so this class caches: it reloads on start,
on SIGHUP, and when a managed file's mtime changes.  Stat-ing the sops files
needs no key, so that poll stays on this side.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

from .config import KeeperConfig, SecretsConfig
from .keeper import KeeperError, fetch_values
from .redact import EligibilityPolicy

log = logging.getLogger("faramir.secrets")

SECRET_URI_RE = re.compile(r"^secret://(?P<ref>[A-Za-z0-9][A-Za-z0-9._/-]*)$")
INLINE_TOKEN_RE = re.compile(r"\{\{SECRET:(?P<ref>[A-Za-z0-9][A-Za-z0-9._/-]*)\}\}")


class SecretError(Exception):
    """The value set could not be loaded, or an unknown ref was requested."""


def parse_secret_uri(uri: str) -> str:
    m = SECRET_URI_RE.match(uri.strip())
    if not m:
        raise SecretError(
            f"invalid secret reference {uri!r}; expected secret://path/to/key"
        )
    return m.group("ref")


@dataclass
class _FileState:
    path: str
    mtime: float
    size: int


class SecretStore:
    """Thread-safe, mtime-refreshed view of every managed secret value."""

    def __init__(self, config: SecretsConfig, keeper: KeeperConfig) -> None:
        self.config = config
        self.keeper = keeper
        self.policy = EligibilityPolicy(
            min_length=config.min_length,
            min_unique_chars=config.min_unique_chars,
            min_entropy_bits_per_char=config.min_entropy_bits_per_char,
        )
        self._lock = threading.RLock()
        self._values: dict[str, str] = {}
        self._refused: dict[str, str] = {}
        self._state: list[_FileState] = []
        self._checked_at = 0.0
        self.load_errors: list[str] = []

    # -- loading -----------------------------------------------------------

    def reload(self) -> None:
        """Re-fetch every value from the keeper.  On startup and on SIGHUP."""
        state: list[_FileState] = []
        errors: list[str] = []
        for path in self.config.files:
            try:
                st = os.stat(path)
            except OSError as exc:
                errors.append(f"{path}: {exc.strerror}")
                continue
            state.append(_FileState(path, st.st_mtime, st.st_size))

        try:
            values, keeper_errors = fetch_values(self.keeper.socket_path)
        except KeeperError as exc:
            # Keep the previous value set rather than dropping to empty.  An
            # empty set means nothing is redacted, which is the worst possible
            # response to "the keeper is briefly unreachable".
            with self._lock:
                self.load_errors = [*errors, str(exc)]
                self._state = state
                self._checked_at = time.monotonic()
            log.error("keeper unreachable, keeping the previous value set: %s", exc)
            return
        errors.extend(keeper_errors)

        # A value the redactor cannot cover is not loaded at all.  Serving it
        # would put it in a child's environment with nothing to catch it on
        # the way out, and the ref is useless to an attacker who cannot obtain
        # the value, so there is nothing here to withhold from the agent.
        redactable: dict[str, str] = {}
        refused: dict[str, str] = {}
        for ref, value in values.items():
            reason = self.policy.check(value)
            if reason is None:
                redactable[ref] = value
            else:
                refused[ref] = reason

        with self._lock:
            self._values = redactable
            self._refused = refused
            self._state = state
            self.load_errors = errors
            self._checked_at = time.monotonic()

        for err in errors:
            log.error("secret load: %s", err)
        for ref, reason in sorted(refused.items()):
            log.warning(
                "secret %s was NOT loaded (%s) -- it cannot be redacted, so "
                "the broker refuses to inject it; lengthen it",
                ref,
                reason,
            )
        log.info(
            "loaded %d secret refs from %d file(s), %d refused as not redactable",
            len(redactable),
            len(state),
            len(refused),
        )

    def refresh_if_stale(self) -> None:
        """Cheap mtime poll; reloads when a managed file changed on disk."""
        with self._lock:
            interval = self.config.refresh_interval_sec
            if interval and time.monotonic() - self._checked_at < interval:
                return
            self._checked_at = time.monotonic()
            previous = {(s.path, s.mtime, s.size) for s in self._state}
            paths = list(self.config.files)
        current = set()
        for path in paths:
            try:
                st = os.stat(path)
            except OSError:
                continue
            current.add((path, st.st_mtime, st.st_size))
        if current != previous:
            log.info("managed secret file changed on disk; reloading")
            self.reload()

    # -- access ------------------------------------------------------------

    def refs(self) -> list[str]:
        """Names only.  Safe to hand to the agent."""
        with self._lock:
            return sorted(self._values)

    def value(self, ref: str) -> str:
        with self._lock:
            try:
                return self._values[ref]
            except KeyError:
                # Naming the refusal separately: "unknown ref" would send the
                # operator looking for a typo in a ref that is spelled right.
                reason = self._refused.get(ref)
                if reason is not None:
                    raise SecretError(
                        f"secret {ref} was refused at load ({reason}); it cannot "
                        "be redacted, so it is not injectable. Lengthen the value."
                    ) from None
                raise SecretError(f"unknown secret ref: {ref}") from None

    def pairs(self) -> list[tuple[str, str]]:
        """Every (ref, value) pair: the input to the redactor's value set.

        The age key is deliberately absent.  It used to be listed here so that
        a child which printed it got a token instead of the key; no child can
        obtain it any more, so that property now holds by construction rather
        than by the matcher catching it on the way out.
        """
        with self._lock:
            return sorted(self._values.items())

    def describe(self) -> dict[str, Any]:
        """Loaded-state summary.  Safe for the agent-facing wire."""
        with self._lock:
            return {
                "files": [s.path for s in self._state],
                "ref_count": len(self._values),
                "errors": list(self.load_errors),
            }

    def describe_for_operator(self) -> dict[str, Any]:
        """``describe()`` plus the refs refused at load, and why.

        Refusing a value stops the broker injecting it; it does not stop the
        value reaching the output some other way, and a refused value is absent
        from the redactor, so it arrives in plaintext when it does.  The list is
        therefore still a shortlist of exactly which secrets are never
        tokenized, which is targeting information for the agent and a repair
        list for the operator.  Only the operator gets it.

        One snapshot: a reload between the counts and the refused refs would
        otherwise report a set that never existed.
        """
        with self._lock:
            return {
                **self.describe(),
                "not_redactable": dict(sorted(self._refused.items())),
            }

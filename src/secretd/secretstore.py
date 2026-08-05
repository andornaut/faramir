"""Decrypts the sops files the broker manages and holds the full value set.

Two things matter here:

1. The value set is *every* secret the broker knows about, not just the ones
   injected into the current command.  ``ansible-playbook`` decrypts vars
   internally, so an injector-based tool cannot mask a var it never injected.
   The redactor has to know the lot regardless of injection path.
2. Plaintext lives only in this process's heap.  It is never written to disk,
   never placed in an argv, and the age key is read from
   ``$CREDENTIALS_DIRECTORY`` (systemd ``LoadCredential=``), not from a path
   the child could re-read.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .config import SecretsConfig
from .redact import EligibilityPolicy

log = logging.getLogger("secretd.secrets")

SECRET_URI_RE = re.compile(r"^secret://(?P<ref>[A-Za-z0-9][A-Za-z0-9._/-]*)$")
INLINE_TOKEN_RE = re.compile(r"\{\{SECRET:(?P<ref>[A-Za-z0-9][A-Za-z0-9._/-]*)\}\}")


class SecretError(Exception):
    """Decryption failed, or an unknown ref was requested."""


def parse_secret_uri(uri: str) -> str:
    m = SECRET_URI_RE.match(uri.strip())
    if not m:
        raise SecretError(
            f"invalid secret reference {uri!r}; expected secret://path/to/key"
        )
    return m.group("ref")


def _flatten(node: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Walk decrypted YAML/JSON into ``path/to/key`` -> string pairs."""
    if isinstance(node, dict):
        for key, value in node.items():
            # Exactly the top-level 'sops' key, which is sops' own metadata
            # block.  A prefix match at any depth would silently drop real
            # secrets (sops_backup_token, home/sopsuser) from the value set,
            # and a dropped secret is never redacted and never warned about.
            if prefix == "" and str(key) == "sops":
                continue
            yield from _flatten(value, f"{prefix}/{key}" if prefix else str(key))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _flatten(value, f"{prefix}/{i}" if prefix else str(i))
    elif isinstance(node, bool) or node is None:
        return  # never secret, and "True"/"False" would redact half the output
    else:
        yield prefix, str(node)


@dataclass
class _FileState:
    path: str
    mtime: float
    size: int


class SecretStore:
    """Thread-safe, mtime-refreshed view of every managed sops file."""

    def __init__(self, config: SecretsConfig) -> None:
        self.config = config
        self.policy = EligibilityPolicy(
            min_length=config.min_length,
            min_unique_chars=config.min_unique_chars,
            min_entropy_bits_per_char=config.min_entropy_bits_per_char,
        )
        self._lock = threading.RLock()
        self._values: dict[str, str] = {}
        self._state: list[_FileState] = []
        self._checked_at = 0.0
        self._age_key: str | None = None
        self.load_errors: list[str] = []

    # -- key material ------------------------------------------------------

    AGE_KEY_REF = "broker/age-key"

    def age_key_material(self) -> str | None:
        """The age private key, for children that must decrypt (Ansible).

        Handing this to a child is a real concession: whoever holds it can
        decrypt every managed file.  It is mitigated two ways -- only allowlist
        rules with ``provide_age_key = true`` receive it, and the key itself is
        part of the redaction value set (see :meth:`pairs`), so a child that
        prints it gets a token.
        """
        return self._age_key_material()

    def _age_key_material(self) -> str | None:
        """Read the age private key from the systemd credential directory."""
        if self._age_key is not None:
            return self._age_key
        candidates = []
        creds = os.environ.get("CREDENTIALS_DIRECTORY")
        if creds and self.config.age_key_credential:
            candidates.append(os.path.join(creds, self.config.age_key_credential))
        if self.config.age_key_file:
            candidates.append(self.config.age_key_file)
        for candidate in candidates:
            try:
                self._age_key = Path(candidate).read_text("utf-8")
                log.info("loaded age key from %s", candidate)
                return self._age_key
            except OSError:
                continue
        log.warning("no age key available (tried: %s)", ", ".join(candidates) or "none")
        return None

    # -- loading -----------------------------------------------------------

    def _decrypt(self, path: str) -> dict[str, Any]:
        argv = [a.replace("{file}", path) for a in self.config.decrypt_command]
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": "C.UTF-8",
        }
        key = self._age_key_material()
        if key:
            env["SOPS_AGE_KEY"] = key
        try:
            proc = subprocess.run(
                argv, capture_output=True, env=env, timeout=60, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SecretError(f"{path}: running {argv[0]} failed: {exc}") from exc
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            raise SecretError(
                f"{path}: decrypt failed ({proc.returncode}): "
                f"{detail[-1] if detail else 'no output'}"
            )
        try:
            return json.loads(proc.stdout.decode("utf-8", "replace"))
        except json.JSONDecodeError as exc:
            raise SecretError(f"{path}: decrypted output is not JSON: {exc}") from exc

    def reload(self) -> None:
        """Re-read every managed file.  Called on startup and on SIGHUP."""
        values: dict[str, str] = {}
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
                tree = self._decrypt(path)
            except SecretError as exc:
                errors.append(str(exc))
                continue
            for ref, value in _flatten(tree):
                if ref in values and values[ref] != value:
                    log.warning("secret ref %s defined more than once; last wins", ref)
                values[ref] = value

        with self._lock:
            self._values = values
            self._state = state
            self.load_errors = errors
            self._checked_at = time.monotonic()

        for err in errors:
            log.error("secret load: %s", err)
        weak = [(ref, r) for ref, v in values.items() if (r := self.policy.check(v))]
        for ref, reason in weak:
            log.warning(
                "secret %s will NOT be redacted (%s) -- lengthen it or it can "
                "reach the model in plaintext",
                ref,
                reason,
            )
        log.info(
            "loaded %d secret refs from %d file(s), %d not redactable",
            len(values),
            len(state),
            len(weak),
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
                raise SecretError(f"unknown secret ref: {ref}") from None

    def pairs(self) -> list[tuple[str, str]]:
        """Every (ref, value) pair -- the input to the redactor's value set.

        Includes the age private key.  A child that can decrypt can also print
        the key it decrypted with, and that would be a far worse leak than any
        single credential.
        """
        with self._lock:
            out = sorted(self._values.items())
        key = self._age_key_material()
        if key:
            for line in key.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append((self.AGE_KEY_REF, line))
        return out

    def weak_refs(self) -> list[tuple[str, str]]:
        with self._lock:
            return [
                (ref, reason)
                for ref, value in sorted(self._values.items())
                if (reason := self.policy.check(value))
            ]

    def describe(self) -> dict[str, Any]:
        with self._lock:
            return {
                "files": [s.path for s in self._state],
                "ref_count": len(self._values),
                "errors": list(self.load_errors),
                "not_redactable": [ref for ref, _ in self.weak_refs()],
            }

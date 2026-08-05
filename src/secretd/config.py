"""Configuration for secretd: /etc/secretd/config.toml.

Everything the broker will do is described here.  The allowlist is
default-deny: a command that matches no ``[[allow]]`` rule is refused.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = "/etc/secretd/config.toml"

_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class ConfigError(Exception):
    """Raised for a malformed or unsafe configuration."""


def _section(factory: Any, raw: dict[str, Any], where: str, **extra: Any) -> Any:
    """Build one config dataclass, reporting a typo as a ConfigError.

    A bare ``Factory(**raw)`` raises TypeError, which nothing up the stack
    converts, so a single mistyped key makes ``secretd --check`` die with a
    traceback instead of naming the offending line.
    """
    known = {f.name for f in fields(factory)}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(
            f"{where}: unknown key(s): {', '.join(unknown)}; "
            f"known keys: {', '.join(sorted(known))}"
        )
    try:
        return factory(**raw, **extra)
    except TypeError as exc:
        raise ConfigError(f"{where}: {exc}") from exc


def _table(raw: dict[str, Any], key: str, where: str) -> dict[str, Any]:
    """One ``[section]`` as a dict, rejecting a scalar written in its place.

    ``dict(scalar)`` raises ValueError, which nothing up the stack converts, so
    ``server = "0660"`` in place of ``[server]`` would kill ``--check`` with a
    traceback rather than name the section.
    """
    value = raw.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{where}: expected a [{key}] table, got {type(value).__name__}")
    return dict(value)


def _octal_mode(value: Any, where: str) -> int:
    """Accept both ``"0660"`` and TOML's own ``0o660``.

    TOML parses ``0o660`` to the int 432, which is already the mode, so it is
    taken as-is; running it through ``int(str(v), 8)`` would reinterpret it as
    0o432 -- write for others, no read for the group -- without any error.

    The range check is what catches an unquoted decimal ``660``, which is a
    plausible typo for ``0o660`` and would otherwise mean 0o1224.  Every real
    mode fits in 0o777, so anything above it is a mistake either way.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ConfigError(f"{where}: expected an octal string or integer")
    if isinstance(value, str):
        try:
            value = int(value, 8)
        except ValueError as exc:
            raise ConfigError(f"{where}: {value!r} is not octal") from exc
    if not 0 <= value <= 0o777:
        hint = ""
        digits = str(value)
        # Only suggest the octal spelling when it is one: 660 is a typo for
        # 0o660, but 4095 is not a mode at all.
        if set(digits) <= set("01234567") and int(digits, 8) <= 0o777:
            hint = f'; {value} looks like decimal, write it as "{digits}" or 0o{digits}'
        raise ConfigError(f"{where}: out of range, expected 0 to 0o777{hint}")
    return value


def _compile_all(patterns: list[str], where: str) -> list[re.Pattern[str]]:
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error as exc:
            raise ConfigError(f"{where}: bad regex {p!r}: {exc}") from exc
    return out


@dataclass(frozen=True)
class AllowRule:
    """One entry in the default-deny allowlist."""

    name: str
    argv0: re.Pattern[str]
    args_allow: list[re.Pattern[str]] = field(default_factory=list)
    args_deny: list[re.Pattern[str]] = field(default_factory=list)
    cwd_allow: list[re.Pattern[str]] = field(default_factory=list)
    max_timeout_sec: int | None = None
    # Whether this program gets SOPS_AGE_KEY in its environment.  Ansible has
    # to decrypt vars itself, so it needs the key; a shell must never get it.
    # The key is in the redaction value set regardless, so it cannot be printed
    # in the clear -- but keeping it out of most children is still cheaper than
    # relying on that.
    provide_age_key: bool = False

    @classmethod
    def parse(cls, raw: dict[str, Any], index: int) -> "AllowRule":
        name = raw.get("name") or f"rule[{index}]"
        if "argv0" not in raw:
            raise ConfigError(f"allow rule {name!r}: missing 'argv0'")
        return cls(
            name=str(name),
            argv0=_compile_all([raw["argv0"]], f"allow rule {name!r} argv0")[0],
            args_allow=_compile_all(
                list(raw.get("args_allow", [])), f"allow rule {name!r} args_allow"
            ),
            args_deny=_compile_all(
                list(raw.get("args_deny", [])), f"allow rule {name!r} args_deny"
            ),
            cwd_allow=_compile_all(
                list(raw.get("cwd_allow", [])), f"allow rule {name!r} cwd_allow"
            ),
            max_timeout_sec=raw.get("max_timeout_sec"),
            provide_age_key=bool(raw.get("provide_age_key", False)),
        )


@dataclass(frozen=True)
class ServerConfig:
    socket_path: str = "/run/secretd/sock"
    socket_mode: int = 0o660
    max_concurrency: int = 4
    max_request_bytes: int = 262144
    allowed_uids: list[int] = field(default_factory=list)
    allowed_groups: list[str] = field(default_factory=lambda: ["devwork"])


@dataclass(frozen=True)
class ExecConfig:
    default_cwd: str = "/srv/ansible-ctrl"
    default_timeout_sec: int = 600
    max_timeout_sec: int = 3600
    max_output_bytes: int = 1048576
    allowed_bin_dirs: list[str] = field(
        default_factory=lambda: ["/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin"]
    )
    base_env: dict[str, str] = field(
        default_factory=lambda: {
            "PATH": _DEFAULT_PATH,
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "DEBIAN_FRONTEND": "noninteractive",
        }
    )
    term_cols: int = 120
    term_rows: int = 40
    kill_grace_sec: int = 5


@dataclass(frozen=True)
class SecretsConfig:
    files: list[str] = field(default_factory=list)
    decrypt_command: list[str] = field(
        default_factory=lambda: ["sops", "--output-type", "json", "--decrypt", "{file}"]
    )
    age_key_credential: str = "age_key"
    age_key_file: str = ""
    refresh_interval_sec: int = 5
    min_length: int = 8
    min_unique_chars: int = 4
    min_entropy_bits_per_char: float = 1.5


@dataclass(frozen=True)
class AuditConfig:
    raw_log: str = "/var/log/secretd/raw.log"
    max_record_bytes: int = 4194304


@dataclass(frozen=True)
class SyncConfig:
    """Mediated ``git`` pull from the agent's working tree into /srv.

    The agent authors playbooks; the broker only ever executes committed ones.
    """

    enabled: bool = False
    source: str = "/home/agent/work/ansible-ctrl"
    dest: str = "/srv/ansible-ctrl"
    default_ref: str = "HEAD"
    allowed_refs: list[re.Pattern[str]] = field(default_factory=list)
    git: str = "/usr/bin/git"
    clean: bool = True
    timeout_sec: int = 120


@dataclass(frozen=True)
class Config:
    path: str
    server: ServerConfig
    exec: ExecConfig
    secrets: SecretsConfig
    audit: AuditConfig
    sync: SyncConfig
    allow: list[AllowRule]

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> "Config":
        path = str(path or os.environ.get("SECRETD_CONFIG") or DEFAULT_CONFIG_PATH)
        try:
            raw = tomllib.loads(Path(path).read_text("utf-8"))
        except FileNotFoundError as exc:
            raise ConfigError(f"config not found: {path}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
        return cls.from_dict(raw, path)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], path: str = "<memory>") -> "Config":
        server_raw = _table(raw, "server", path)
        mode = server_raw.pop("socket_mode", None)
        server = _section(
            ServerConfig,
            server_raw,
            f"{path}: [server]",
            **(
                {"socket_mode": _octal_mode(mode, f"{path}: server.socket_mode")}
                if mode is not None
                else {}
            ),
        )

        exec_cfg = _section(
            ExecConfig, _table(raw, "exec", path), f"{path}: [exec]"
        )
        secrets = _section(
            SecretsConfig, _table(raw, "secrets", path), f"{path}: [secrets]"
        )
        audit = _section(AuditConfig, _table(raw, "audit", path), f"{path}: [audit]")

        sync_raw = _table(raw, "sync", path)
        sync_refs = _compile_all(list(sync_raw.pop("allowed_refs", [])), "sync.allowed_refs")
        sync = _section(
            SyncConfig, sync_raw, f"{path}: [sync]", allowed_refs=sync_refs
        )

        allow_raw = raw.get("allow", [])
        if not isinstance(allow_raw, list) or not all(
            isinstance(r, dict) for r in allow_raw
        ):
            raise ConfigError(f"{path}: [[allow]] must be a list of tables")
        allow = [AllowRule.parse(r, i) for i, r in enumerate(allow_raw)]
        if not allow:
            raise ConfigError(
                f"{path}: no [[allow]] rules; the broker would refuse every command"
            )
        return cls(
            path=path,
            server=server,
            exec=exec_cfg,
            secrets=secrets,
            audit=audit,
            sync=sync,
            allow=allow,
        )

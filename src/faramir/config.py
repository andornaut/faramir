"""Configuration for faramir: /etc/faramir/config.toml.

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

DEFAULT_CONFIG_PATH = "/etc/faramir/config.toml"

_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class ConfigError(Exception):
    """Raised for a malformed or unsafe configuration."""


def _section(factory: Any, raw: dict[str, Any], where: str, **extra: Any) -> Any:
    """Build one config dataclass, reporting a typo as a ConfigError.

    A bare ``Factory(**raw)`` raises TypeError, which nothing up the stack
    converts, so a single mistyped key makes ``faramir-broker --check`` die with a
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

    The error names the accepted spellings rather than guessing which one was
    meant.  tomllib parses ``0o1000`` and ``512`` to the same int, so the
    original spelling is not recoverable here and any specific advice would be
    wrong for one of them.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ConfigError(f"{where}: expected an octal string or integer")
    if isinstance(value, str):
        try:
            value = int(value, 8)
        except ValueError as exc:
            raise ConfigError(f"{where}: {value!r} is not octal") from exc
    if not 0 <= value <= 0o777:
        raise ConfigError(
            f"{where}: out of range, expected 0 to 0o777; write the mode in "
            'octal, as "0660" or 0o660'
        )
    return value


def _positive_int(value: Any, where: str) -> int | None:
    """An optional positive integer, rejected here rather than at use time.

    An unvalidated ``max_timeout_sec`` survives ``--check`` and then fails
    inside ``min()`` when a request finally exercises the rule.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}: expected an integer, got {type(value).__name__}")
    if value <= 0:
        raise ConfigError(f"{where}: expected a positive integer, got {value}")
    return value


def _count(value: Any, where: str) -> int | None:
    """An optional argument count.  Zero is meaningful, so not _positive_int."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}: expected an integer, got {type(value).__name__}")
    if value < 0:
        raise ConfigError(f"{where}: expected zero or more, got {value}")
    return value


def _compile_all(patterns: Any, where: str) -> list[re.Pattern[str]]:
    """Compile a list of regexes, rejecting anything that is not one.

    The type check is the point.  ``list("^main$")`` splits a bare string into
    single characters, one of which is ``$``, and ``$`` matches everything --
    so a missing pair of brackets silently turns a default-deny allowlist into
    match-anything with no error at ``--check`` time.
    """
    if isinstance(patterns, str) or not isinstance(patterns, (list, tuple)):
        raise ConfigError(
            f"{where}: expected a list of regex strings, got "
            f"{type(patterns).__name__}"
            + (f" (write it as [{patterns!r}])" if isinstance(patterns, str) else "")
        )
    out = []
    for p in patterns:
        if not isinstance(p, str):
            raise ConfigError(
                f"{where}: expected a regex string, got {type(p).__name__}: {p!r}"
            )
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
    # How many arguments the rule accepts.  Separate from args_allow, which
    # only describes the arguments that are present: without min_args a rule
    # that permits exactly one variable name still permits none at all.
    min_args: int | None = None
    max_args: int | None = None

    @classmethod
    def parse(cls, raw: dict[str, Any], index: int) -> "AllowRule":
        name = raw.get("name") or f"rule[{index}]"
        if "argv0" not in raw:
            raise ConfigError(f"allow rule {name!r}: missing 'argv0'")
        if "provide_age_key" in raw:
            # Nothing the broker executes receives the age key any more: the
            # keeper holds it and returns values only.  Failing loudly matters
            # because silently ignoring the flag would leave a config that
            # still reads as though Ansible were being handed the master key.
            raise ConfigError(
                f"allow rule {name!r}: 'provide_age_key' no longer exists. The "
                "keeper holds the age key and no child ever receives it; have "
                "Ansible read its vars from the environment instead (see "
                "docs/ansible-sops.md)."
            )
        min_args = _count(raw.get("min_args"), f"allow rule {name!r} min_args")
        max_args = _count(raw.get("max_args"), f"allow rule {name!r} max_args")
        if min_args is not None and max_args is not None and min_args > max_args:
            raise ConfigError(
                f"allow rule {name!r}: min_args ({min_args}) exceeds "
                f"max_args ({max_args}), so the rule can never match"
            )
        # No list() around the raw values: it would split a bare string into
        # characters before _compile_all could reject it, which is the bug that
        # check exists to catch.
        return cls(
            name=str(name),
            argv0=_compile_all([raw["argv0"]], f"allow rule {name!r} argv0")[0],
            args_allow=_compile_all(
                raw.get("args_allow", []), f"allow rule {name!r} args_allow"
            ),
            args_deny=_compile_all(
                raw.get("args_deny", []), f"allow rule {name!r} args_deny"
            ),
            cwd_allow=_compile_all(
                raw.get("cwd_allow", []), f"allow rule {name!r} cwd_allow"
            ),
            max_timeout_sec=_positive_int(
                raw.get("max_timeout_sec"), f"allow rule {name!r} max_timeout_sec"
            ),
            min_args=min_args,
            max_args=max_args,
        )


@dataclass(frozen=True)
class ServerConfig:
    socket_path: str = "/run/faramir/broker.sock"
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
class KeeperConfig:
    """The process that holds the age key.

    Separate uid, separate socket, and no operation that returns the key.  The
    broker is the only client; ``allowed_users`` is what says so.
    """

    socket_path: str = "/run/faramir/keeper.sock"
    socket_mode: int = 0o660
    allowed_users: list[str] = field(default_factory=lambda: ["faramir-broker"])
    allowed_groups: list[str] = field(default_factory=list)
    age_key_credential: str = "age_key"
    age_key_file: str = ""


@dataclass(frozen=True)
class ExecutorConfig:
    """The process that forks brokered commands.

    Its uid holds nothing: no age key, no secret values, no audit log, no write
    access to the execution checkout.  A child forked by the broker instead
    would inherit all four.
    """

    socket_path: str = "/run/faramir/exec.sock"
    socket_mode: int = 0o660
    allowed_users: list[str] = field(default_factory=lambda: ["faramir-broker"])
    allowed_groups: list[str] = field(default_factory=list)
    max_concurrency: int = 16


@dataclass(frozen=True)
class SshConfig:
    """An ssh-agent the broker owns, for keys the executor must not read.

    With no ``keys`` no agent is started and nothing is injected; SSH then
    authenticates however the operator has arranged it for the executor's uid.
    """

    keys: list[str] = field(default_factory=list)
    agent_socket: str = "/run/faramir/ssh-agent.sock"
    agent_socket_mode: int = 0o660
    exec_group: str = "faramir-exec"
    ssh_agent: str = "/usr/bin/ssh-agent"
    ssh_add: str = "/usr/bin/ssh-add"


@dataclass(frozen=True)
class SecretsConfig:
    files: list[str] = field(default_factory=list)
    decrypt_command: list[str] = field(
        default_factory=lambda: ["sops", "--output-type", "json", "--decrypt", "{file}"]
    )
    refresh_interval_sec: int = 5
    min_length: int = 8
    min_unique_chars: int = 4
    min_entropy_bits_per_char: float = 1.5


@dataclass(frozen=True)
class AuditConfig:
    raw_log: str = "/var/log/faramir/raw.log"
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
    keeper: KeeperConfig
    executor: ExecutorConfig
    exec: ExecConfig
    ssh: SshConfig
    secrets: SecretsConfig
    audit: AuditConfig
    sync: SyncConfig
    allow: list[AllowRule]

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> "Config":
        path = str(path or os.environ.get("FARAMIR_CONFIG") or DEFAULT_CONFIG_PATH)
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

        keeper_raw = _table(raw, "keeper", path)
        keeper_mode = keeper_raw.pop("socket_mode", None)
        keeper = _section(
            KeeperConfig,
            keeper_raw,
            f"{path}: [keeper]",
            **(
                {"socket_mode": _octal_mode(keeper_mode, f"{path}: keeper.socket_mode")}
                if keeper_mode is not None
                else {}
            ),
        )

        executor_raw = _table(raw, "executor", path)
        executor_mode = executor_raw.pop("socket_mode", None)
        executor = _section(
            ExecutorConfig,
            executor_raw,
            f"{path}: [executor]",
            **(
                {
                    "socket_mode": _octal_mode(
                        executor_mode, f"{path}: executor.socket_mode"
                    )
                }
                if executor_mode is not None
                else {}
            ),
        )

        exec_cfg = _section(
            ExecConfig, _table(raw, "exec", path), f"{path}: [exec]"
        )
        secrets_raw = _table(raw, "secrets", path)
        moved = [k for k in ("age_key_credential", "age_key_file") if k in secrets_raw]
        if moved:
            raise ConfigError(
                f"{path}: [secrets] {', '.join(moved)} moved to [keeper]; the "
                "broker no longer reads the age key at all"
            )
        secrets = _section(SecretsConfig, secrets_raw, f"{path}: [secrets]")

        ssh_raw = _table(raw, "ssh", path)
        ssh_mode = ssh_raw.pop("agent_socket_mode", None)
        ssh = _section(
            SshConfig,
            ssh_raw,
            f"{path}: [ssh]",
            **(
                {
                    "agent_socket_mode": _octal_mode(
                        ssh_mode, f"{path}: ssh.agent_socket_mode"
                    )
                }
                if ssh_mode is not None
                else {}
            ),
        )
        audit = _section(AuditConfig, _table(raw, "audit", path), f"{path}: [audit]")

        sync_raw = _table(raw, "sync", path)
        sync_refs = _compile_all(
            sync_raw.pop("allowed_refs", []), f"{path}: sync.allowed_refs"
        )
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
            keeper=keeper,
            executor=executor,
            exec=exec_cfg,
            ssh=ssh,
            secrets=secrets,
            audit=audit,
            sync=sync,
            allow=allow,
        )

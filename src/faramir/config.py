"""Configuration for faramir: /etc/faramir/config.toml.

Everything the broker will do is described here.  There is no command
allowlist: the broker runs what it is asked to run, as a uid that holds
nothing, and redacts the output.  See ``resolve.py`` for why the allowlist was
removed rather than merely widened.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = "/etc/faramir/config.toml"

_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class ConfigError(Exception):
    """Raised for a malformed or unsafe configuration."""


def _reject_unknown_keys(factory: Any, raw: dict[str, Any], where: str) -> None:
    """Fail on a mistyped key, naming it and the alternatives.

    Every settable key is a field of the dataclass it configures, so the
    dataclass is the schema.  Rules that are parsed by hand rather than built
    from ``raw`` still have to come through here: a key that is merely ignored
    leaves the config reading as though it had taken effect.
    """
    known = {f.name for f in fields(factory)}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(
            f"{where}: unknown key(s): {', '.join(unknown)}; "
            f"known keys: {', '.join(sorted(known))}"
        )


def _section(factory: Any, raw: dict[str, Any], where: str, **extra: Any) -> Any:
    """Build one config dataclass, reporting a typo as a ConfigError.

    A bare ``Factory(**raw)`` raises TypeError, which nothing up the stack
    converts, so a single mistyped key makes ``faramir-broker --check`` die with a
    traceback instead of naming the offending line.
    """
    _reject_unknown_keys(factory, raw, where)
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
    # No default: where commands run is a property of the deployment, and a
    # broker that guesses would run them somewhere the operator never named.
    default_cwd: str = ""
    default_timeout_sec: int = 600
    max_timeout_sec: int = 3600
    max_output_bytes: int = 1048576
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

    Its uid holds nothing: no age key, no secret values, no audit log, no SSH
    keys.  A child forked by the broker instead would inherit all four.
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
class Config:
    path: str
    server: ServerConfig
    keeper: KeeperConfig
    executor: ExecutorConfig
    exec: ExecConfig
    ssh: SshConfig
    secrets: SecretsConfig
    audit: AuditConfig

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

        exec_raw = _table(raw, "exec", path)
        if "allowed_bin_dirs" in exec_raw:
            # It went with the allowlist: it bounded argv[0] only, so any rule
            # permitting bash or python walked straight past it, and what it
            # reliably did instead was refuse every pipx, venv, shim and /opt
            # install on the host.
            raise ConfigError(
                f"{path}: [exec] allowed_bin_dirs no longer exists. A bare "
                "command name is looked up on [exec.base_env] PATH, which is "
                "the PATH the child gets; put a venv or shim directory there."
            )
        exec_cfg = _section(ExecConfig, exec_raw, f"{path}: [exec]")
        if not exec_cfg.default_cwd:
            raise ConfigError(
                f"{path}: [exec] default_cwd is required; name the directory "
                "brokered commands run in (see etc/config.toml)"
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

        if "sync" in raw:
            # Ignoring the section would leave a config that reads as though
            # the broker still executed a separate checkout, and an [exec]
            # default_cwd still pointing at a directory nothing populates.
            raise ConfigError(
                f"{path}: [sync] no longer exists. Brokered commands run in "
                "the agent's working tree directly, so there is nothing to "
                "promote: delete the section and point [exec] default_cwd and "
                "[secrets] files at that tree."
            )

        if "allow" in raw:
            # Ignoring the rules would leave a config that reads as though
            # commands were still being constrained by it.
            raise ConfigError(
                f"{path}: [[allow]] no longer exists. The broker runs what it "
                "is asked to run, as a uid that holds nothing, and redacts the "
                "output; a rule permitting any interpreter reached past every "
                "constraint these expressed. Delete the [[allow]] tables."
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
        )

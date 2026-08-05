"""Wire protocol: newline-delimited JSON, one request, one response.

Request (op defaults to "exec")::

    {"cmd": ["ansible-playbook", "site.yml", "--limit", "routers"],
     "cwd": "/srv/ansible-ctrl",
     "env_refs": {"ROUTER_PW": "secret://home/router/admin"},
     "timeout_sec": 600}

Response::

    {"exit_code": 0,
     "output": "…redacted, ANSI-stripped, stdout+stderr merged…",
     "truncated": false,
     "redactions": [{"token": "«SECRET:home/router/admin»", "count": 3}],
     "log_id": "2026-08-05T14:22:01Z-a91f"}

Two rules that are not negotiable:

* Secrets are injected **as environment variables only**.  There is no way to
  ask for a value to be substituted into argv -- a value in argv shows up in
  ``ps`` output, in ``/proc/<pid>/cmdline``, and in the child's own error
  messages.
* ``cmd`` is an array.  The broker never passes a string to ``sh -c``.  A
  caller who wants a pipeline sends ``["bash", "-lc", "…"]`` explicitly, and
  that has to match the allowlist like anything else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .secretstore import INLINE_TOKEN_RE, parse_secret_uri

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Names the broker sets itself; a caller may not overwrite them.
RESERVED_ENV = {
    "PATH",
    "HOME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "IFS",
    "BASH_ENV",
    "ENV",
    "SOPS_AGE_KEY",
    "SOPS_AGE_KEY_FILE",
    "CREDENTIALS_DIRECTORY",
}

OPS = ("exec", "sync", "list_secrets", "status")


class ProtocolError(Exception):
    """Malformed request."""


@dataclass
class Request:
    op: str = "exec"
    cmd: list[str] = field(default_factory=list)
    cwd: str | None = None
    env_refs: dict[str, str] = field(default_factory=dict)
    timeout_sec: int | None = None
    ref: str | None = None  # sync only

    @classmethod
    def parse(cls, payload: Any) -> "Request":
        if not isinstance(payload, dict):
            raise ProtocolError("request must be a JSON object")
        op = payload.get("op", "exec")
        if op not in OPS:
            raise ProtocolError(f"unknown op {op!r}; expected one of {', '.join(OPS)}")

        cmd = payload.get("cmd", [])
        if op == "exec":
            if isinstance(cmd, str):
                raise ProtocolError(
                    "'cmd' must be an array, not a string; the broker never "
                    "invokes a shell for you -- send ['bash', '-lc', '…']"
                )
            if not isinstance(cmd, list) or not cmd:
                raise ProtocolError("'cmd' must be a non-empty array of strings")
            if not all(isinstance(a, str) for a in cmd):
                raise ProtocolError("'cmd' must contain only strings")

        cwd = payload.get("cwd")
        if cwd is not None and (not isinstance(cwd, str) or not cwd.startswith("/")):
            raise ProtocolError("'cwd' must be an absolute path")

        env_refs_raw = payload.get("env_refs", {}) or {}
        if not isinstance(env_refs_raw, dict):
            raise ProtocolError("'env_refs' must be an object of NAME -> secret:// URI")
        env_refs: dict[str, str] = {}
        for name, uri in env_refs_raw.items():
            if not isinstance(name, str) or not ENV_NAME_RE.match(name):
                raise ProtocolError(f"invalid environment variable name: {name!r}")
            if name in RESERVED_ENV:
                raise ProtocolError(f"{name} is reserved and cannot be overwritten")
            if not isinstance(uri, str):
                raise ProtocolError(f"env_refs[{name}] must be a secret:// URI string")
            env_refs[name] = uri

        timeout = payload.get("timeout_sec")
        if timeout is not None:
            if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
                raise ProtocolError("'timeout_sec' must be a positive integer")

        ref = payload.get("ref")
        if ref is not None and not isinstance(ref, str):
            raise ProtocolError("'ref' must be a string")

        return cls(
            op=op,
            cmd=list(cmd) if isinstance(cmd, list) else [],
            cwd=cwd,
            env_refs=env_refs,
            timeout_sec=timeout,
            ref=ref,
        )


def env_name_for_ref(ref: str) -> str:
    """Deterministic variable name for an inline ``{{SECRET:…}}`` token."""
    return "SECRETD_" + re.sub(r"[^A-Za-z0-9]+", "_", ref).upper().strip("_")


def resolve_inline_tokens(
    cmd: list[str], env_refs: dict[str, str]
) -> tuple[list[str], dict[str, str]]:
    """Rewrite ``{{SECRET:ref}}`` in argv into a shell *variable reference*.

    The token is a readability affordance for the caller.  It never expands to
    a value here: it becomes ``${VAR}``, and ``VAR`` is added to the injected
    environment.  If the caller already bound that ref to a name, that name is
    reused.  Note this only expands if the program itself is a shell -- which
    is the point: the value still never appears in any argv.
    """
    by_ref = {parse_secret_uri(uri): name for name, uri in env_refs.items()}
    extra: dict[str, str] = {}
    rewritten: list[str] = []
    for arg in cmd:
        def replace(m: re.Match[str]) -> str:
            ref = m.group("ref")
            name = by_ref.get(ref)
            if name is None:
                name = env_name_for_ref(ref)
                by_ref[ref] = name
                extra[name] = f"secret://{ref}"
            return "${" + name + "}"

        rewritten.append(INLINE_TOKEN_RE.sub(replace, arg))
    return rewritten, {**env_refs, **extra}


def error_response(code: str, message: str, log_id: str | None = None) -> dict[str, Any]:
    return {
        "exit_code": None,
        "output": "",
        "truncated": False,
        "redactions": [],
        "log_id": log_id,
        "error": {"code": code, "message": message},
    }

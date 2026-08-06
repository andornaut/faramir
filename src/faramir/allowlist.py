"""Command allowlist.

A request is executed only if some ``[[allow]]`` rule matches ``cmd[0]`` *and*
every argument passes that rule's constraints *and* the working directory is
permitted.  Denials are explicit about which check failed so the agent can
correct itself instead of guessing.

How wide the rules are is the operator's choice, and a rule of ``argv0 = '.'``
is a legitimate one: what keeps plaintext out of the agent's context is the uid
split and the redactor, and neither runs through here.  Even the widest rule is
still bounded by ``allowed_bin_dirs``, and every match is audited.
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass
from typing import Sequence

from .config import AllowRule, ExecConfig


class DeniedError(Exception):
    """The request does not match the allowlist."""


@dataclass(frozen=True)
class Decision:
    rule: AllowRule
    argv0_path: str


def _resolve_argv0(argv0: str, exec_cfg: ExecConfig) -> tuple[str, str]:
    """Return ``(basename, resolved_path)`` for the program to execute.

    A bare name is resolved against the configured PATH; an explicit path must
    live under ``allowed_bin_dirs``.  Both are then checked against the rule's
    ``argv0`` regex by basename, so a rule cannot be bypassed by spelling the
    path differently.
    """
    if "/" in argv0:
        resolved = os.path.realpath(argv0)
    else:
        found = None
        for directory in exec_cfg.base_env.get("PATH", "").split(":"):
            candidate = os.path.join(directory, argv0)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                found = candidate
                break
        if found is None:
            raise DeniedError(f"{argv0}: not found on the broker's PATH")
        resolved = os.path.realpath(found)

    directory = os.path.dirname(resolved)
    if not any(
        directory == d or directory.startswith(d.rstrip("/") + "/")
        for d in exec_cfg.allowed_bin_dirs
    ):
        raise DeniedError(
            f"{argv0}: resolves to {resolved}, which is outside allowed_bin_dirs "
            f"({', '.join(exec_cfg.allowed_bin_dirs)})"
        )
    if not os.access(resolved, os.X_OK):
        raise DeniedError(f"{argv0}: {resolved} is not executable by the broker")
    return os.path.basename(resolved), resolved


def _check_cwd(rule: AllowRule, cwd: str) -> str | None:
    if not rule.cwd_allow:
        return None
    normalised = posixpath.normpath(cwd)
    if any(p.search(normalised) for p in rule.cwd_allow):
        return None
    return f"cwd {normalised!r} is not permitted by rule {rule.name!r}"


def _check_args(rule: AllowRule, args: Sequence[str]) -> str | None:
    # Count first.  ``args_allow`` constrains the arguments that are *present*,
    # so a rule that carefully describes its one permitted argument still lets
    # the bare command through -- which for ``printenv`` means dumping the whole
    # child environment rather than naming one variable.
    if rule.min_args is not None and len(args) < rule.min_args:
        return (
            f"rule {rule.name!r} requires at least {rule.min_args} argument(s), "
            f"got {len(args)}"
        )
    if rule.max_args is not None and len(args) > rule.max_args:
        return (
            f"rule {rule.name!r} permits at most {rule.max_args} argument(s), "
            f"got {len(args)}"
        )
    for arg in args:
        for deny in rule.args_deny:
            if deny.search(arg):
                return (
                    f"argument {arg!r} is denied by rule {rule.name!r} "
                    f"(pattern {deny.pattern!r})"
                )
        if rule.args_allow and not any(p.search(arg) for p in rule.args_allow):
            return f"argument {arg!r} is not permitted by rule {rule.name!r}"
    return None


def authorize(
    cmd: Sequence[str], cwd: str, rules: Sequence[AllowRule], exec_cfg: ExecConfig
) -> Decision:
    """Return the matching rule, or raise :class:`DeniedError`."""
    if not cmd:
        raise DeniedError("empty command")

    # Match on the requested name first, so an unknown program is reported as
    # "not in the allowlist" rather than as a PATH lookup failure.
    requested = os.path.basename(cmd[0])
    candidates = [r for r in rules if r.argv0.search(requested)]
    if not candidates:
        raise DeniedError(
            f"{requested!r} is not in the allowlist. Permitted programs: "
            f"{', '.join(sorted({r.name for r in rules}))}"
        )

    # Then resolve, and re-check: a symlink must not smuggle in another binary.
    basename, resolved = _resolve_argv0(cmd[0], exec_cfg)
    candidates = [r for r in candidates if r.argv0.search(basename)]
    if not candidates:
        raise DeniedError(
            f"{cmd[0]} resolves to {resolved}, which no allowlist rule permits"
        )

    reasons: list[str] = []
    for rule in candidates:
        reason = _check_cwd(rule, cwd) or _check_args(rule, cmd[1:])
        if reason is None:
            return Decision(rule=rule, argv0_path=resolved)
        reasons.append(reason)
    raise DeniedError("; ".join(reasons))

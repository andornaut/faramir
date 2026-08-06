"""Turn the caller's ``cmd[0]`` into the absolute path the executor will run.

This is all that is left of what used to be a default-deny allowlist.  The
allowlist was removed because it never carried a security property: what keeps
plaintext out of the agent's context is the uid split and the redactor, and a
rule permitting any interpreter -- ``bash``, ``python``, ``env`` -- reached
straight past every constraint it expressed.  It cost an operator a rule per
program and cost the agent a denial per mistake, in exchange for tidiness.

What remains is genuinely needed: the broker sends the executor an absolute
path, so somebody has to work out which file a name refers to, and doing that
wrong means running a *different* file.

Two rules, both about agreeing with the child's own view of the world:

* A bare name is looked up on ``[exec.base_env] PATH`` -- the PATH the child
  will actually get, so a tool in a venv or a pipx install is reached by
  putting it there.
* A relative path is resolved against the request's ``cwd``, because that is
  where the child runs.  Resolving it against the broker's own working
  directory would silently execute a different file of the same name.
"""

from __future__ import annotations

import os

from .config import ExecConfig


class ResolveError(Exception):
    """``cmd[0]`` does not name a program the broker can start."""


def resolve_program(argv0: str, cwd: str, exec_cfg: ExecConfig) -> str:
    """Return the absolute, symlink-resolved path for ``argv0``."""
    if not argv0:
        raise ResolveError("empty command")

    if "/" in argv0:
        resolved = os.path.realpath(os.path.join(cwd, argv0))
        if not os.path.isfile(resolved):
            raise ResolveError(f"{argv0}: no such program (resolved to {resolved})")
    else:
        path = exec_cfg.base_env.get("PATH", "")
        found = None
        for directory in path.split(":"):
            candidate = os.path.join(directory, argv0)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                found = candidate
                break
        if found is None:
            raise ResolveError(
                f"{argv0}: not found on the broker's PATH ({path}). A program "
                "installed elsewhere -- a venv, pipx, a version-manager shim -- "
                "needs its directory on [exec.base_env] PATH, or an absolute "
                "path in cmd[0]."
            )
        resolved = os.path.realpath(found)

    if not os.access(resolved, os.X_OK):
        raise ResolveError(f"{argv0}: {resolved} is not executable by the broker")
    return resolved

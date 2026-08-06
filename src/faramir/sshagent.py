"""An ssh-agent held by the broker, usable by children that cannot read its keys.

Brokered commands run as ``faramir-exec``.  The SSH keys that reach managed
hosts have to be usable from there, and the obvious way to arrange that is to
put them in that uid's home -- at which point every brokered command can read
them, and a leaked fleet key is permanent in a way a leaked password is not.

So the broker keeps the key files under its own uid, loads them into an agent
it owns, and passes only ``SSH_AUTH_SOCK`` to the child.  The child can
authenticate to managed hosts for as long as the broker is running.  It cannot
read the keys, and it cannot ptrace the agent, which belongs to another uid.

Entirely optional: with no ``[ssh] keys`` configured no agent is started and
nothing is injected, and it is up to the operator to arrange authentication
(usually by putting the keys in the executor's own home instead).
"""

from __future__ import annotations

import grp
import logging
import os
import subprocess
import time

from .config import SshConfig

log = logging.getLogger("faramir.ssh")

_SOCKET_WAIT_SEC = 10.0


class SshAgent:
    """Lifecycle of the broker's own ssh-agent.  Safe to start with no keys."""

    def __init__(self, config: SshConfig) -> None:
        self.config = config
        self._proc: subprocess.Popen[bytes] | None = None
        self._socket: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.config.keys)

    def env(self) -> dict[str, str]:
        """What to add to a child's environment.  Empty unless the agent runs."""
        return {"SSH_AUTH_SOCK": self._socket} if self._socket else {}

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if not self.enabled:
            log.info("no [ssh] keys configured; not starting an agent")
            return
        path = self.config.agent_socket
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.exists(path):
                os.unlink(path)
        except OSError as exc:
            log.error("cannot prepare %s: %s", path, exc)
            return

        # -D keeps it in the foreground, so it is an ordinary child of this
        # process and dies with it rather than lingering with the keys loaded.
        try:
            self._proc = subprocess.Popen(
                [self.config.ssh_agent, "-D", "-a", path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        except OSError as exc:
            log.error("cannot start %s: %s", self.config.ssh_agent, exc)
            return

        if not self._await_socket(path):
            log.error("ssh-agent did not create %s; SSH keys will be unavailable", path)
            self.stop()
            return

        self._grant_executor_access(path)
        self._socket = path
        loaded = sum(1 for key in self.config.keys if self._add(key, path))
        log.info("ssh-agent on %s with %d/%d key(s)", path, loaded, len(self.config.keys))
        if not loaded:
            log.error("no SSH keys loaded; commands needing SSH will fail to authenticate")

    def _await_socket(self, path: str) -> bool:
        deadline = time.monotonic() + _SOCKET_WAIT_SEC
        while time.monotonic() < deadline:
            if os.path.exists(path):
                return True
            if self._proc is not None and self._proc.poll() is not None:
                return False
            time.sleep(0.05)
        return False

    def _grant_executor_access(self, path: str) -> None:
        """Let the executor's uid connect, and nothing else.

        ssh-agent creates its socket 0600.  The chown needs the broker to be a
        member of the target group, which the unit arranges with
        ``SupplementaryGroups=``.
        """
        group = self.config.exec_group
        if not group:
            return
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            log.error("group %s does not exist; the executor cannot use the agent", group)
            return
        try:
            os.chown(path, -1, gid)
            os.chmod(path, self.config.agent_socket_mode)
        except OSError as exc:
            log.error(
                "cannot hand %s to group %s (%s); is the broker a member of it?",
                path,
                group,
                exc,
            )

    def _add(self, key: str, socket_path: str) -> bool:
        env = {
            "SSH_AUTH_SOCK": socket_path,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": os.environ.get("HOME", "/tmp"),
            # A key with a passphrase must fail immediately rather than block
            # startup waiting for input nobody will ever type.
            "SSH_ASKPASS_REQUIRE": "never",
            "DISPLAY": "",
        }
        try:
            proc = subprocess.run(
                [self.config.ssh_add, key],
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.error("ssh-add %s: %s", key, exc)
            return False
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            log.error(
                "ssh-add %s failed: %s", key, detail[-1] if detail else "no output"
            )
            return False
        return True

    def stop(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if self._socket:
            try:
                os.unlink(self._socket)
            except OSError:
                pass
        self._socket = None

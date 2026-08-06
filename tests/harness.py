"""Spins up a real broker against real sops+age secrets, in a temp directory.

Everything here is genuine: a real age keypair, a real sops-encrypted file, a
real Unix socket, real PTY execution.  Only the paths are temporary, and the
allowlist is the shipped ``etc/config.toml`` with its paths rewritten, so the
tests exercise the policy that actually ships.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"

sys.path.insert(0, str(SRC))

from faramir.client import BrokerUnavailable, call  # noqa: E402

ROUTER_PW = "Tr0ub4dor-and-3-horses-stapled"
API_TOKEN = "sk-live-9f2b7c41d8e6a03b5719ce84"
SHORT_PW = "abc"  # below the redaction floor on purpose


def have(*programs: str) -> bool:
    return all(shutil.which(p) for p in programs)


class Broker:
    """A running broker, with its own key, secrets, socket and log."""

    def __init__(self, *, ssh_keys: bool = False) -> None:
        self.ssh_keys = ssh_keys
        self.root = Path(tempfile.mkdtemp(prefix="faramir-e2e-"))
        self.workdir = self.root / "srv" / "ansible-ctrl"
        self.agent_tree = self.root / "home" / "agent" / "work" / "ansible-ctrl"
        self.creds = self.root / "creds"
        self.socket_path = self.root / "sock"
        self.keeper_socket_path = self.root / "keeper.sock"
        self.exec_socket_path = self.root / "exec.sock"
        self.raw_log = self.root / "log" / "raw.log"
        self.config_path = self.root / "config.toml"
        self.proc: subprocess.Popen[bytes] | None = None
        self.keeper_proc: subprocess.Popen[bytes] | None = None
        self.exec_proc: subprocess.Popen[bytes] | None = None
        self.stderr_path = self.root / "faramir.stderr"
        self.keeper_stderr_path = self.root / "faramir-keeper.stderr"
        self.exec_stderr_path = self.root / "faramir-exec.stderr"
        self.ssh_key = self.root / "ssh" / "id_ed25519"
        self.ssh_agent_socket = self.root / "ssh-agent.sock"

    # -- setup -------------------------------------------------------------

    def build(self) -> "Broker":
        for path in (self.workdir, self.agent_tree, self.creds, self.raw_log.parent):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.creds, 0o700)
        self._keygen()
        if self.ssh_keys:
            self._ssh_keygen()
        self._write_secrets()
        self._write_config()
        self._write_playbooks()
        return self

    def _keygen(self) -> None:
        key = self.creds / "age_key"
        subprocess.run(
            ["age-keygen", "-o", str(key)], check=True, capture_output=True
        )
        os.chmod(key, 0o400)
        text = key.read_text()
        self.age_public = [
            w for line in text.splitlines() for w in line.split() if w.startswith("age1")
        ][0]
        self.age_private = [
            line.strip()
            for line in text.splitlines()
            if line.strip().startswith("AGE-SECRET-KEY-")
        ][0]

    def _ssh_keygen(self) -> None:
        """A key the broker holds and the child may only use through the agent."""
        self.ssh_key.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.ssh_key.parent, 0o700)
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "faramir-test",
             "-f", str(self.ssh_key)],
            check=True,
            capture_output=True,
        )

    def _write_secrets(self) -> None:
        plain = self.root / "plain.yml"
        plain.write_text(
            "home:\n"
            "  router:\n"
            f"    admin: {ROUTER_PW}\n"
            "  api:\n"
            f"    token: {API_TOKEN}\n"
            f"vault_router_password: {ROUTER_PW}\n"
            f"short_pin: {SHORT_PW}\n"
        )
        self.secrets_file = self.workdir / "group_vars" / "all" / "vault.sops.yml"
        self.secrets_file.parent.mkdir(parents=True, exist_ok=True)
        encrypted = subprocess.run(
            ["sops", "--encrypt", "--age", self.age_public, str(plain)],
            check=True,
            capture_output=True,
        ).stdout
        self.secrets_file.write_bytes(encrypted)
        plain.unlink()
        assert ROUTER_PW not in self.secrets_file.read_text()

    def _write_config(self) -> None:
        """Reuse the shipped allowlist verbatim; only rewrite the paths."""
        text = (REPO / "etc" / "config.toml").read_text()
        replacements = {
            "/srv/ansible-ctrl": str(self.workdir),
            "/home/agent/work/ansible-ctrl": str(self.agent_tree),
            "/run/faramir/broker.sock": str(self.socket_path),
            "/run/faramir/keeper.sock": str(self.keeper_socket_path),
            "/run/faramir/exec.sock": str(self.exec_socket_path),
            "/var/log/faramir/raw.log": str(self.raw_log),
            '"/usr/bin/git"': f'"{shutil.which("git") or "/usr/bin/git"}"',
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        # Ansible resolves the sops vars itself, so the *child* needs sops on
        # its PATH.  The shipped base_env lists only the system directories; on
        # a machine where sops is installed elsewhere the playbook test would
        # fail with 127 rather than tell you why.
        sops = shutil.which("sops")
        if sops:
            text = re.sub(
                r'^(PATH = ")',
                lambda m: m.group(1) + os.path.dirname(sops) + ":",
                text,
                count=1,
                flags=re.MULTILINE,
            )
        if self.ssh_keys:
            text = text.replace(
                "keys = []", f'keys = ["{self.ssh_key}"]'
            ).replace(
                '"/run/faramir/ssh-agent.sock"', f'"{self.ssh_agent_socket}"'
            ).replace(
                'exec_group = "faramir-exec"', 'exec_group = ""'
            )
        # The temp dir lives outside allowed_bin_dirs; keep the shipped list.
        self.config_path.write_text(text)

    def _write_playbooks(self) -> None:
        (self.workdir / "ansible.cfg").write_text(
            "[defaults]\nstdout_callback = default\nretry_files_enabled = False\n"
        )
        (self.workdir / "inventory.ini").write_text(
            "[local]\nlocalhost ansible_connection=local\n"
        )
        # How Ansible is meant to get its credentials now: the broker injects
        # the named refs as environment variables and group_vars reads them.
        # The playbook then prints one, which is exactly the accident that
        # redaction exists for.
        (self.workdir / "site.yml").write_text(
            "- hosts: local\n"
            "  gather_facts: false\n"
            "  vars:\n"
            "    vault_router_password: \"{{ lookup('env', 'ROUTER_PW') }}\"\n"
            "  tasks:\n"
            "    - name: print the vault variable\n"
            "      debug:\n"
            "        var: vault_router_password\n"
            "    - name: print it again inside a message\n"
            "      debug:\n"
            "        msg: \"router password is {{ vault_router_password }}\"\n"
        )
        # The old arrangement, kept as a negative test: a playbook that tries
        # to decrypt the sops file itself must now fail, because no child of
        # the broker holds the age key.
        (self.workdir / "decrypt.yml").write_text(
            "- hosts: local\n"
            "  gather_facts: false\n"
            "  vars:\n"
            "    vault: \"{{ lookup('pipe', 'sops --output-type json -d "
            "group_vars/all/vault.sops.yml') | from_json }}\"\n"
            "  tasks:\n"
            "    - name: print the vault variable\n"
            "      debug:\n"
            "        var: vault.vault_router_password\n"
        )

    # -- lifecycle ---------------------------------------------------------

    def _env(self, *, with_credentials: bool) -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(SRC),
            "PYTHONUNBUFFERED": "1",
            "HOME": str(self.root),
            "LANG": "C.UTF-8",
        }
        # Only the keeper is given the age key, exactly as in the deployment,
        # where LoadCredential= lives on faramir-keeper.service alone.
        if with_credentials:
            env["CREDENTIALS_DIRECTORY"] = str(self.creds)
        return env

    def start(self, timeout: float = 20.0) -> "Broker":
        """Start the keeper, the executor, then the broker.

        All three run as the current uid.  That is enough to exercise the
        protocols and the process split; the uid boundaries themselves only
        exist on a real deployment, and tests/verify.sh is what checks them
        there.
        """
        self._keeper_stderr = open(self.keeper_stderr_path, "wb")
        self.keeper_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "faramir.keeper",
                "-c",
                str(self.config_path),
            ],
            env=self._env(with_credentials=True),
            stdout=self._keeper_stderr,
            stderr=self._keeper_stderr,
            cwd=str(self.root),
        )
        self._await_socket(
            self.keeper_socket_path, self.keeper_proc, timeout, "the keeper"
        )

        self._exec_stderr = open(self.exec_stderr_path, "wb")
        self.exec_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "faramir.execserver",
                "-c",
                str(self.config_path),
            ],
            env=self._env(with_credentials=False),
            stdout=self._exec_stderr,
            stderr=self._exec_stderr,
            cwd=str(self.root),
        )
        self._await_socket(
            self.exec_socket_path, self.exec_proc, timeout, "the executor"
        )

        self._stderr = open(self.stderr_path, "wb")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "faramir", "-c", str(self.config_path)],
            env=self._env(with_credentials=False),
            stdout=self._stderr,
            stderr=self._stderr,
            cwd=str(self.root),
        )
        self._await_socket(self.socket_path, self.proc, timeout, "the broker")
        return self

    def _await_socket(
        self,
        path: Path,
        proc: subprocess.Popen[bytes],
        timeout: float,
        what: str,
    ) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if path.exists():
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                        probe.connect(str(path))
                    return
                except OSError:
                    pass
            if proc.poll() is not None:
                raise RuntimeError(f"{what} exited early:\n{self.log()}")
            time.sleep(0.05)
        raise RuntimeError(f"{what} did not start:\n{self.log()}")

    def stop(self) -> None:
        for proc in (self.proc, self.exec_proc, self.keeper_proc):
            if proc and proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for attr in ("_stderr", "_exec_stderr", "_keeper_stderr"):
            handle = getattr(self, attr, None)
            if handle:
                handle.close()

    def cleanup(self) -> None:
        self.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    # -- helpers -----------------------------------------------------------

    def log(self) -> str:
        parts = []
        for label, path in (
            ("keeper", self.keeper_stderr_path),
            ("executor", self.exec_stderr_path),
            ("broker", self.stderr_path),
        ):
            try:
                text = path.read_text()
            except OSError:
                continue
            if text:
                parts.append(f"--- {label} ---\n{text}")
        return "\n".join(parts)

    def keeper_call(self, request: dict) -> dict:
        """Talk to the keeper directly, the way only the broker should."""
        return call(request, str(self.keeper_socket_path), timeout=60)

    def store_describe(self, *, include_weak: bool = False) -> dict:
        """What `faramir-broker --check` prints: operator-side, out of band."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "faramir",
                "-c",
                str(self.config_path),
                "--check",
            ],
            env=self._env(with_credentials=False),
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(self.root),
        )
        described = json.loads(result.stdout.split("allow rules:")[0])
        if not include_weak:
            described.pop("not_redactable", None)
        return described

    def exec_call(self, request: dict) -> dict:
        """Talk to the executor directly, without passing a terminal fd."""
        return call(request, str(self.exec_socket_path), timeout=60)

    def raw_log_text(self) -> str:
        try:
            return self.raw_log.read_text()
        except OSError:
            return ""

    def call(self, request: dict) -> dict:
        return call(request, str(self.socket_path), timeout=180)

    def run(self, cmd: list[str], env_refs: dict | None = None, **kw) -> dict:
        request = {"op": "exec", "cmd": cmd}
        if env_refs:
            request["env_refs"] = env_refs
        request.update(kw)
        return self.call(request)

    def cli(self, args: list[str]) -> subprocess.CompletedProcess:
        """Drive the real CLI, the way the agent would."""
        env = dict(os.environ)
        env["FARAMIR_SOCKET"] = str(self.socket_path)
        env["FARAMIR_LIB"] = str(SRC)
        return subprocess.run(
            [sys.executable, str(REPO / "bin" / "faramir"), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )

    def mcp(self, messages: list[dict]) -> list[dict]:
        """Drive the real MCP server over stdio."""
        env = dict(os.environ)
        env["FARAMIR_SOCKET"] = str(self.socket_path)
        env["FARAMIR_LIB"] = str(SRC)
        payload = "".join(json.dumps(m) + "\n" for m in messages)
        proc = subprocess.run(
            [sys.executable, str(REPO / "bin" / "faramir-mcp")],
            input=payload,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]

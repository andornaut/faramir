"""Spins up a real broker against real sops+age secrets, in a temp directory.

Everything here is genuine: a real age keypair, a real sops-encrypted file, a
real Unix socket, real PTY execution.  Only the paths are temporary, and the
allowlist is the shipped ``etc/config.toml`` with its paths rewritten, so the
tests exercise the policy that actually ships.
"""

from __future__ import annotations

import json
import os
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

from secretd.client import BrokerUnavailable, call  # noqa: E402

ROUTER_PW = "Tr0ub4dor-and-3-horses-stapled"
API_TOKEN = "sk-live-9f2b7c41d8e6a03b5719ce84"
SHORT_PW = "abc"  # below the redaction floor on purpose


def have(*programs: str) -> bool:
    return all(shutil.which(p) for p in programs)


class Broker:
    """A running secretd, with its own key, secrets, socket and log."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="secretd-e2e-"))
        self.workdir = self.root / "srv" / "ansible-ctrl"
        self.agent_tree = self.root / "home" / "agent" / "work" / "ansible-ctrl"
        self.creds = self.root / "creds"
        self.socket_path = self.root / "sock"
        self.raw_log = self.root / "log" / "raw.log"
        self.config_path = self.root / "config.toml"
        self.proc: subprocess.Popen[bytes] | None = None
        self.stderr_path = self.root / "secretd.stderr"

    # -- setup -------------------------------------------------------------

    def build(self) -> "Broker":
        for path in (self.workdir, self.agent_tree, self.creds, self.raw_log.parent):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.creds, 0o700)
        self._keygen()
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
            "/run/secretd/sock": str(self.socket_path),
            "/var/log/secretd/raw.log": str(self.raw_log),
            '"/usr/bin/git"': f'"{shutil.which("git") or "/usr/bin/git"}"',
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        # The temp dir lives outside allowed_bin_dirs; keep the shipped list.
        self.config_path.write_text(text)

    def _write_playbooks(self) -> None:
        (self.workdir / "ansible.cfg").write_text(
            "[defaults]\nstdout_callback = default\nretry_files_enabled = False\n"
        )
        (self.workdir / "inventory.ini").write_text(
            "[local]\nlocalhost ansible_connection=local\n"
        )
        # Resolves the sops file at run time and then prints the variable --
        # exactly the accident redaction exists for.  In production this
        # lookup is the community.sops vars plugin; the property under test
        # (Ansible decrypts internally, then prints) is identical.
        (self.workdir / "site.yml").write_text(
            "- hosts: local\n"
            "  gather_facts: false\n"
            "  vars:\n"
            "    vault: \"{{ lookup('pipe', 'sops --output-type json -d "
            "group_vars/all/vault.sops.yml') | from_json }}\"\n"
            "  tasks:\n"
            "    - name: print the vault variable\n"
            "      debug:\n"
            "        var: vault.vault_router_password\n"
            "    - name: print it again inside a message\n"
            "      debug:\n"
            "        msg: \"router password is {{ vault.home.router.admin }}\"\n"
        )

    # -- lifecycle ---------------------------------------------------------

    def start(self, timeout: float = 20.0) -> "Broker":
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(SRC),
            "PYTHONUNBUFFERED": "1",
            "CREDENTIALS_DIRECTORY": str(self.creds),
            "HOME": str(self.root),
            "LANG": "C.UTF-8",
        }
        self._stderr = open(self.stderr_path, "wb")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "secretd", "-c", str(self.config_path)],
            env=env,
            stdout=self._stderr,
            stderr=self._stderr,
            cwd=str(self.root),
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.socket_path.exists():
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                        probe.connect(str(self.socket_path))
                    return self
                except OSError:
                    pass
            if self.proc.poll() is not None:
                raise RuntimeError(f"secretd exited early:\n{self.log()}")
            time.sleep(0.05)
        raise RuntimeError(f"secretd did not start:\n{self.log()}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if getattr(self, "_stderr", None):
            self._stderr.close()

    def cleanup(self) -> None:
        self.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    # -- helpers -----------------------------------------------------------

    def log(self) -> str:
        try:
            return self.stderr_path.read_text()
        except OSError:
            return ""

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

    def secure_run_cli(self, args: list[str]) -> subprocess.CompletedProcess:
        """Drive the real CLI, the way the agent would."""
        env = dict(os.environ)
        env["SECRETD_SOCKET"] = str(self.socket_path)
        env["SECRETD_LIB"] = str(SRC)
        return subprocess.run(
            [sys.executable, str(REPO / "bin" / "secure-run"), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )

    def mcp(self, messages: list[dict]) -> list[dict]:
        """Drive the real MCP server over stdio."""
        env = dict(os.environ)
        env["SECRETD_SOCKET"] = str(self.socket_path)
        env["SECRETD_LIB"] = str(SRC)
        payload = "".join(json.dumps(m) + "\n" for m in messages)
        proc = subprocess.run(
            [sys.executable, str(REPO / "bin" / "secretd-mcp")],
            input=payload,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]

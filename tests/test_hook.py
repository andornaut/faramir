"""PreToolUse hook.

The hook is ergonomics with teeth, not the boundary -- but a deterministic
block with a corrective message changes behaviour far more reliably than prose
in a config file, so it is worth testing that it fires on the obvious cases and
stays out of the way otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from unittest import mock

REPO = os.path.join(os.path.dirname(__file__), "..")
HOOK = os.path.join(REPO, "agent", "hooks", "pretooluse-guard.py")
PATTERNS = os.path.join(REPO, "agent", "hooks", "deny-patterns.txt")


def load_guard():
    """Import the hook as a module, to assert on its constants."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("faramir_guard", HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_hook(command: str, tool: str = "Bash") -> dict:
    env = dict(os.environ)
    env["FARAMIR_DENY_PATTERNS"] = PATTERNS
    result = subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps({"tool_name": tool, "tool_input": {"command": command}}),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if not result.stdout.strip():
        return {}
    return json.loads(result.stdout)


def decision(command: str, tool: str = "Bash") -> str | None:
    out = run_hook(command, tool)
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision")


class TestDenied(unittest.TestCase):
    CASES = [
        "ansible-vault view group_vars/all/vault.yml",
        "ansible-vault decrypt secrets.yml",
        "ansible-vault edit vault.yml",
        "sops -d group_vars/all/vault.sops.yml",
        "sops --decrypt secrets.yaml",
        "sops decrypt group_vars/all/vault.sops.yml",  # sops 3.9+ subcommand
        "age --decrypt -i key.txt file.age",
        "op read op://vault/item/field",
        "pass show servers/router",
        "printenv",
        "printenv ROUTER_PW",
        "env",
        "cat /etc/faramir/age.key",
        "cat group_vars/all/vault.yml",
        "cat .env.production",
        "head -5 ~/.ssh/id_rsa",
        "cat /proc/1234/environ",
        "sudo -u faramir-broker cat /var/log/faramir/raw.log",
        "journalctl -u faramir-broker",
    ]

    def test_denied(self):
        for command in self.CASES:
            with self.subTest(command=command):
                self.assertEqual(decision(command), "deny")

    def test_denial_names_the_alternative(self):
        out = run_hook("printenv ROUTER_PW")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("faramir_run", reason)
        self.assertIn("secret://", reason)
        self.assertIn("matched deny pattern", reason)


class TestAllowed(unittest.TestCase):
    CASES = [
        "ls -la",
        "git status",
        "ansible-playbook --syntax-check site.yml",
        "vim group_vars/all/vault.sops.yml",  # editing an encrypted file is fine
        "env | wc -l",  # piped: not a context dump
        "grep -r hostname roles/",
        "faramir run -- printenv ROUTER_PW",  # the sanctioned path
        "faramir run --env PW=secret://a/b -- ansible-playbook site.yml",
    ]

    def test_allowed(self):
        for command in self.CASES:
            with self.subTest(command=command):
                self.assertIsNone(decision(command))

    def test_other_tools_are_ignored(self):
        self.assertIsNone(decision("printenv", tool="Read"))

    def test_malformed_payload_does_not_block(self):
        result = subprocess.run(
            [sys.executable, HOOK], input="not json", capture_output=True, text=True, timeout=30
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")


class TestFaramirExemption(unittest.TestCase):
    """The exemption covers the faramir invocation, not the whole line."""

    def test_trailing_command_is_still_checked(self):
        for command in [
            "faramir status; printenv ROUTER_PW",
            "faramir status && cat /etc/faramir/age.key",
            "faramir status | printenv",
            "faramir list-secrets\nprintenv ROUTER_PW",
        ]:
            with self.subTest(command=command):
                self.assertEqual(decision(command), "deny")

    def test_chained_faramir_is_still_exempt(self):
        self.assertIsNone(
            decision("faramir status && faramir run -- ansible-playbook site.yml")
        )


class TestFailClosed(unittest.TestCase):
    def test_missing_patterns_file_still_denies(self):
        env = dict(os.environ)
        env["FARAMIR_DENY_PATTERNS"] = "/nonexistent/deny-patterns.txt"
        result = subprocess.run(
            [sys.executable, HOOK],
            input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "printenv"}}),
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        self.assertIn("deny", result.stdout)

    def test_fallback_is_not_weaker_than_the_shipped_list(self):
        """A patterns file the hook cannot read must not widen what is allowed.

        The hook runs as the agent uid; if the installed file ever becomes
        unreadable again, the fallback is what stands between the agent and a
        plaintext credential in the context window.
        """
        with open(PATTERNS, encoding="utf-8") as fh:
            shipped = [
                line.strip()
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            ]
        # Set comparison, not assertEqual: reordering or regrouping the file
        # does not weaken anything, and CI should not care.
        missing = sorted(set(shipped) - set(load_guard().FALLBACK))
        self.assertEqual(missing, [], f"FALLBACK is missing: {missing}")

    def test_default_patterns_path_is_agent_readable(self):
        """Not under /etc/faramir, which is 0750 faramir-broker:faramir-broker."""
        with mock.patch.dict(os.environ):
            os.environ.pop("FARAMIR_DENY_PATTERNS", None)
            self.assertNotIn("/etc/faramir", load_guard().PATTERNS_FILE)


class TestPatternsFile(unittest.TestCase):
    def test_every_pattern_compiles(self):
        import re

        with open(PATTERNS, encoding="utf-8") as fh:
            for number, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                with self.subTest(line=number):
                    re.compile(line)


if __name__ == "__main__":
    unittest.main()

"""Wire protocol validation.

The two invariants worth testing here are the ones that would quietly put a
plaintext value somewhere it can be read: a shell string instead of an argv,
and a secret substituted into the command line.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from secretd.protocol import (  # noqa: E402
    ProtocolError,
    Request,
    env_name_for_ref,
    resolve_inline_tokens,
)
from secretd.secretstore import SecretError, parse_secret_uri  # noqa: E402


class TestRequestParsing(unittest.TestCase):
    def test_minimal(self):
        req = Request.parse({"cmd": ["ansible-playbook", "site.yml"]})
        self.assertEqual(req.op, "exec")
        self.assertEqual(req.cmd, ["ansible-playbook", "site.yml"])

    def test_shell_string_is_rejected_with_guidance(self):
        with self.assertRaises(ProtocolError) as ctx:
            Request.parse({"cmd": "ansible-playbook site.yml | tee log"})
        self.assertIn("bash", str(ctx.exception))

    def test_empty_cmd_rejected(self):
        with self.assertRaises(ProtocolError):
            Request.parse({"cmd": []})

    def test_non_string_argv_rejected(self):
        with self.assertRaises(ProtocolError):
            Request.parse({"cmd": ["echo", 7]})

    def test_relative_cwd_rejected(self):
        with self.assertRaises(ProtocolError):
            Request.parse({"cmd": ["ansible"], "cwd": "../elsewhere"})

    def test_bad_env_name_rejected(self):
        with self.assertRaises(ProtocolError):
            Request.parse({"cmd": ["ansible"], "env_refs": {"bad name": "secret://a"}})

    def test_reserved_env_name_rejected(self):
        with self.assertRaises(ProtocolError) as ctx:
            Request.parse({"cmd": ["ansible"], "env_refs": {"LD_PRELOAD": "secret://a"}})
        self.assertIn("reserved", str(ctx.exception))

    def test_negative_timeout_rejected(self):
        with self.assertRaises(ProtocolError):
            Request.parse({"cmd": ["ansible"], "timeout_sec": -1})

    def test_bool_timeout_rejected(self):
        with self.assertRaises(ProtocolError):
            Request.parse({"cmd": ["ansible"], "timeout_sec": True})

    def test_unknown_op_rejected(self):
        with self.assertRaises(ProtocolError):
            Request.parse({"op": "rm", "cmd": ["x"]})

    def test_ops_without_cmd(self):
        for op in ("status", "list_secrets", "sync"):
            self.assertEqual(Request.parse({"op": op}).op, op)


class TestSecretUris(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(parse_secret_uri("secret://home/router/admin"), "home/router/admin")

    def test_literal_value_rejected(self):
        with self.assertRaises(SecretError):
            parse_secret_uri("hunter2")

    def test_traversal_rejected(self):
        with self.assertRaises(SecretError):
            parse_secret_uri("secret://../../etc/shadow")


class TestInlineTokens(unittest.TestCase):
    """{{SECRET:…}} is readability sugar; it must never become a value."""

    def test_token_becomes_a_variable_reference(self):
        cmd, env = resolve_inline_tokens(
            ["bash", "-lc", "curl -u admin:{{SECRET:home/router/admin}} https://x"], {}
        )
        name = env_name_for_ref("home/router/admin")
        self.assertIn("${" + name + "}", cmd[2])
        self.assertEqual(env[name], "secret://home/router/admin")

    def test_existing_binding_is_reused(self):
        cmd, env = resolve_inline_tokens(
            ["bash", "-lc", "echo {{SECRET:a/b}}"], {"PW": "secret://a/b"}
        )
        self.assertIn("${PW}", cmd[2])
        self.assertEqual(list(env), ["PW"])

    def test_untouched_when_no_token(self):
        cmd, env = resolve_inline_tokens(["ansible-playbook", "site.yml"], {})
        self.assertEqual(cmd, ["ansible-playbook", "site.yml"])
        self.assertEqual(env, {})

    def test_env_name_is_deterministic(self):
        self.assertEqual(env_name_for_ref("home/router/admin"), "SECRETD_HOME_ROUTER_ADMIN")


if __name__ == "__main__":
    unittest.main()

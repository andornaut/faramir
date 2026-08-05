"""Allowlist is default-deny; these tests pin that down."""

import os
import sys
import tomllib
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from secretd.allowlist import DeniedError, authorize  # noqa: E402
from secretd.config import Config, ConfigError  # noqa: E402

REPO = os.path.join(os.path.dirname(__file__), "..")
SHIPPED_CONFIG = os.path.join(REPO, "etc", "config.toml")


def load_shipped():
    with open(SHIPPED_CONFIG, "rb") as fh:
        return Config.from_dict(tomllib.load(fh), SHIPPED_CONFIG)


class TestShippedAllowlist(unittest.TestCase):
    """The starter allowlist must actually be usable, and actually deny."""

    @classmethod
    def setUpClass(cls):
        cls.config = load_shipped()
        cls.rules = cls.config.allow
        # Point cwd checks at a directory that exists in the test environment.
        cls.cwd = "/srv/ansible-ctrl"

    def check(self, cmd, cwd=None):
        return authorize(cmd, cwd or self.cwd, self.rules, self.config.exec)

    def test_cat_is_denied(self):
        with self.assertRaises(DeniedError) as ctx:
            self.check(["cat", "/etc/passwd"])
        self.assertIn("not in the allowlist", str(ctx.exception))

    def test_denial_names_the_alternatives(self):
        with self.assertRaises(DeniedError) as ctx:
            self.check(["nmap", "10.0.0.0/24"])
        self.assertIn("ansible-playbook", str(ctx.exception))

    def test_printenv_is_allowed(self):
        self.assertEqual(self.check(["printenv", "ROUTER_PW"]).rule.name, "printenv")

    def test_printenv_rejects_a_path_argument(self):
        with self.assertRaises(DeniedError):
            self.check(["printenv", "/etc/shadow"])

    def test_bash_pipeline_is_allowed(self):
        self.assertEqual(
            self.check(["bash", "-lc", "printenv ROUTER_PW | base64"]).rule.name, "bash"
        )

    def test_bash_cannot_read_the_key_directory(self):
        with self.assertRaises(DeniedError):
            self.check(["bash", "-lc", "cat /etc/secretd/age.key"])

    def test_bash_cannot_read_another_process_environ(self):
        with self.assertRaises(DeniedError):
            self.check(["bash", "-lc", "cat /proc/1234/environ"])

    def test_ansible_playbook_allowed(self):
        decision = self.check(["ansible-playbook", "site.yml", "--limit", "routers"])
        self.assertEqual(decision.rule.name, "ansible-playbook")

    def test_ansible_playbook_verbose_allowed(self):
        # -vvv must work: it is one of the accident modes redaction exists for.
        self.check(["ansible-playbook", "site.yml", "-vvv"])

    def test_ansible_playbook_vault_password_file_denied(self):
        with self.assertRaises(DeniedError):
            self.check(["ansible-playbook", "site.yml", "--vault-password-file", "/tmp/p"])

    def test_ansible_playbook_outside_checkout_denied(self):
        with self.assertRaises(DeniedError) as ctx:
            self.check(["ansible-playbook", "site.yml"], cwd="/home/agent/work/ansible-ctrl")
        self.assertIn("cwd", str(ctx.exception))

    def test_curl_config_file_denied(self):
        with self.assertRaises(DeniedError):
            self.check(["curl", "-K", "/tmp/headers"])

    def test_git_write_ops_denied(self):
        with self.assertRaises(DeniedError):
            self.check(["git", "push"])

    def test_absolute_path_still_matches_rule(self):
        decision = self.check(["/usr/bin/printenv", "PATH"])
        self.assertEqual(decision.rule.name, "printenv")

    def test_binary_outside_allowed_dirs_denied(self):
        with self.assertRaises(DeniedError) as ctx:
            self.check(["/tmp/printenv", "PATH"])
        self.assertIn("allowed_bin_dirs", str(ctx.exception))


class TestConfigValidation(unittest.TestCase):
    def test_shipped_config_parses(self):
        config = load_shipped()
        self.assertTrue(config.allow)
        self.assertEqual(config.server.socket_mode, 0o660)

    def test_config_without_rules_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict({"server": {}})

    def test_bad_regex_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict({"allow": [{"name": "x", "argv0": "([unclosed"}]})

    def test_rule_without_argv0_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict({"allow": [{"name": "x"}]})

    def test_empty_command_denied(self):
        config = load_shipped()
        with self.assertRaises(DeniedError):
            authorize([], "/srv", config.allow, config.exec)


if __name__ == "__main__":
    unittest.main()

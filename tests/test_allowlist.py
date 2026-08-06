"""Allowlist is default-deny; these tests pin that down."""

import os
import sys
import tomllib
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from faramir.allowlist import DeniedError, authorize  # noqa: E402
from faramir.config import Config, ConfigError  # noqa: E402

REPO = os.path.join(os.path.dirname(__file__), "..")
SHIPPED_CONFIG = os.path.join(REPO, "etc", "config.toml")
EXAMPLES_DIR = os.path.join(REPO, "etc", "examples")
ANSIBLE_EXAMPLE = os.path.join(EXAMPLES_DIR, "ansible-fleet.toml")


def load_config(path):
    with open(path, "rb") as fh:
        return Config.from_dict(tomllib.load(fh), path)


def load_shipped():
    return load_config(SHIPPED_CONFIG)


class TestShippedAllowlist(unittest.TestCase):
    """The starter allowlist must actually be usable, and actually deny."""

    @classmethod
    def setUpClass(cls):
        cls.config = load_shipped()
        cls.rules = cls.config.allow
        # Point cwd checks at a directory that exists in the test environment.
        cls.cwd = "/srv/faramir"

    def check(self, cmd, cwd=None):
        return authorize(cmd, cwd or self.cwd, self.rules, self.config.exec)

    def test_bare_printenv_is_denied(self):
        # args_allow only constrains the arguments that are present, so
        # without min_args the shipped printenv rule would permit a bare
        # invocation, which dumps the whole child environment.
        with self.assertRaises(DeniedError) as ctx:
            self.check(["printenv"])
        self.assertIn("at least 1", str(ctx.exception))

    def test_printenv_takes_exactly_one_variable(self):
        self.check(["printenv", "ROUTER_PW"])
        with self.assertRaises(DeniedError) as ctx:
            self.check(["printenv", "ROUTER_PW", "API_TOKEN"])
        self.assertIn("at most 1", str(ctx.exception))

    def test_cat_is_denied(self):
        with self.assertRaises(DeniedError) as ctx:
            self.check(["cat", "/etc/passwd"])
        self.assertIn("not in the allowlist", str(ctx.exception))

    def test_denial_names_the_alternatives(self):
        with self.assertRaises(DeniedError) as ctx:
            self.check(["nmap", "10.0.0.0/24"])
        self.assertIn("printenv", str(ctx.exception))

    def test_it_prefers_no_workload(self):
        # The starter demonstrates the broker; which commands a deployment
        # actually runs is the operator's choice, kept in etc/examples/.
        self.assertEqual({r.name for r in self.rules}, {"printenv", "bash"})

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
            self.check(["bash", "-lc", "cat /etc/faramir/age.key"])

    def test_bash_cannot_read_another_process_environ(self):
        with self.assertRaises(DeniedError):
            self.check(["bash", "-lc", "cat /proc/1234/environ"])

    def test_absolute_path_still_matches_rule(self):
        decision = self.check(["/usr/bin/printenv", "PATH"])
        self.assertEqual(decision.rule.name, "printenv")

    def test_binary_outside_allowed_dirs_denied(self):
        with self.assertRaises(DeniedError) as ctx:
            self.check(["/tmp/printenv", "PATH"])
        self.assertIn("allowed_bin_dirs", str(ctx.exception))


class TestTheAnsibleExample(unittest.TestCase):
    """etc/examples/ansible-fleet.toml: a policy for a real workload."""

    @classmethod
    def setUpClass(cls):
        cls.config = load_config(ANSIBLE_EXAMPLE)
        cls.rules = cls.config.allow
        cls.cwd = "/srv/faramir"

    def check(self, cmd, cwd=None):
        return authorize(cmd, cwd or self.cwd, self.rules, self.config.exec)

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
            self.check(["ansible-playbook", "site.yml"], cwd="/home/agent/work/repo")
        self.assertIn("cwd", str(ctx.exception))

    def test_curl_config_file_denied(self):
        with self.assertRaises(DeniedError):
            self.check(["curl", "-K", "/tmp/headers"])

    def test_git_write_ops_denied(self):
        with self.assertRaises(DeniedError):
            self.check(["git", "push"])

    def test_it_keeps_the_starter_rules(self):
        self.assertIn("printenv", {r.name for r in self.rules})


class TestConfigValidation(unittest.TestCase):
    def test_every_example_parses(self):
        # An example nobody loads is an example that rots.
        examples = sorted(
            os.path.join(EXAMPLES_DIR, f)
            for f in os.listdir(EXAMPLES_DIR)
            if f.endswith(".toml")
        )
        self.assertTrue(examples)
        for path in examples:
            with self.subTest(example=os.path.basename(path)):
                self.assertTrue(load_config(path).allow)

    def test_shipped_config_parses(self):
        config = load_shipped()
        self.assertTrue(config.allow)
        self.assertEqual(config.server.socket_mode, 0o660)

    def test_config_without_rules_is_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            Config.from_dict({"exec": {"default_cwd": "/srv/faramir"}, "server": {}})
        self.assertIn("[[allow]]", str(ctx.exception))

    def test_bad_regex_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict(
                {"exec": {"default_cwd": "/srv/faramir"},
                 "allow": [{"name": "x", "argv0": "([unclosed"}]})

    def test_rule_without_argv0_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict(
                {"exec": {"default_cwd": "/srv/faramir"},
                 "allow": [{"name": "x"}]})

    def test_empty_command_denied(self):
        config = load_shipped()
        with self.assertRaises(DeniedError):
            authorize([], "/srv", config.allow, config.exec)


if __name__ == "__main__":
    unittest.main()

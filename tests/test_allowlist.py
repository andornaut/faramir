"""What each shipped policy actually permits.

The starter is deliberately wide and the Ansible example is deliberately
narrow, so between them these pin down both ends: that a permissive rule is
still bounded by ``allowed_bin_dirs``, and that the narrowing machinery
(``cwd_allow``, ``args_deny``, ``min_args``) really bites when it is used.
"""

import os
import shutil
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

# authorize() resolves argv0 on the broker's PATH before it checks anything
# else, so on a host without Ansible these tests would fail with "not found on
# the broker's PATH" -- or worse, pass, because that is a DeniedError too and a
# test asserting a denial cannot tell the two apart.
needs_ansible = unittest.skipUnless(
    shutil.which("ansible-playbook"), "needs ansible-playbook on PATH"
)


def load_config(path):
    with open(path, "rb") as fh:
        return Config.from_dict(tomllib.load(fh), path)


def load_shipped():
    return load_config(SHIPPED_CONFIG)


class TestShippedAllowlist(unittest.TestCase):
    """The starter permits anything on the host, on purpose.

    Ergonomics: an operator who has to write a rule before running anything
    writes a bad one.  The properties that matter do not come from here.
    """

    @classmethod
    def setUpClass(cls):
        cls.config = load_shipped()
        cls.rules = cls.config.allow
        # Point cwd checks at a directory that exists in the test environment.
        cls.cwd = "/home/agent/work/repo"

    def check(self, cmd, cwd=None):
        return authorize(cmd, cwd or self.cwd, self.rules, self.config.exec)

    def test_it_is_one_permissive_rule(self):
        self.assertEqual({r.name for r in self.rules}, {"anything"})

    def test_ordinary_programs_are_allowed(self):
        for cmd in (["printenv", "ROUTER_PW"], ["cat", "/etc/passwd"], ["ls"]):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.check(cmd).rule.name, "anything")

    def test_bash_pipeline_is_allowed(self):
        self.assertEqual(
            self.check(["bash", "-lc", "printenv ROUTER_PW | base64"]).rule.name,
            "anything",
        )

    def test_allowed_bin_dirs_still_bounds_it(self):
        # The one thing 'allow everything' must not mean: running a program the
        # agent just wrote somewhere it can write.
        with self.assertRaises(DeniedError) as ctx:
            self.check(["/tmp/printenv", "PATH"])
        self.assertIn("allowed_bin_dirs", str(ctx.exception))

    def test_args_deny_still_bites(self):
        for arg in ("cat /etc/faramir/age.key", "cat /proc/1234/environ"):
            with self.subTest(arg=arg):
                with self.assertRaises(DeniedError):
                    self.check(["bash", "-lc", arg])

    def test_an_unknown_program_is_still_refused(self):
        # Not by the allowlist -- there is nothing left to deny -- but because
        # it does not resolve on the broker's own PATH.
        with self.assertRaises(DeniedError) as ctx:
            self.check(["definitely-not-installed-xyzzy"])
        self.assertIn("PATH", str(ctx.exception))

    def test_absolute_path_still_matches(self):
        self.assertEqual(self.check(["/usr/bin/printenv", "PATH"]).rule.name, "anything")


class TestTheAnsibleExample(unittest.TestCase):
    """etc/examples/ansible-fleet.toml: a narrow policy for a real workload.

    This is where the constraint machinery is exercised, because this is the
    shipped config that actually uses it.
    """

    CWD = "/home/agent/work/ansible-ctrl"

    @classmethod
    def setUpClass(cls):
        cls.config = load_config(ANSIBLE_EXAMPLE)
        cls.rules = cls.config.allow
        cls.cwd = cls.CWD

    def check(self, cmd, cwd=None):
        return authorize(cmd, cwd or self.cwd, self.rules, self.config.exec)

    @needs_ansible
    def test_ansible_playbook_allowed(self):
        decision = self.check(["ansible-playbook", "site.yml", "--limit", "routers"])
        self.assertEqual(decision.rule.name, "ansible-playbook")

    @needs_ansible
    def test_ansible_playbook_verbose_allowed(self):
        # -vvv must work: it is one of the accident modes redaction exists for.
        self.check(["ansible-playbook", "site.yml", "-vvv"])

    @needs_ansible
    def test_ansible_playbook_vault_password_file_denied(self):
        with self.assertRaises(DeniedError):
            self.check(["ansible-playbook", "site.yml", "--vault-password-file", "/tmp/p"])

    @needs_ansible
    def test_ansible_playbook_outside_the_worktree_denied(self):
        with self.assertRaises(DeniedError) as ctx:
            self.check(["ansible-playbook", "site.yml"], cwd="/home/agent/work/other")
        self.assertIn("cwd", str(ctx.exception))

    def test_cwd_allow_names_this_example_worktree(self):
        # The installer rewrites these along with [exec] default_cwd; if they
        # ever disagree the rule permits nothing and every run is denied.
        self.assertEqual(self.config.exec.default_cwd, self.CWD)

    def test_curl_config_file_denied(self):
        with self.assertRaises(DeniedError):
            self.check(["curl", "-K", "/tmp/headers"])

    def test_git_write_ops_denied(self):
        # The broker runs in the agent's tree now, so a write op here would
        # rewrite the tree the agent is working in.
        with self.assertRaises(DeniedError):
            self.check(["git", "push"])
        with self.assertRaises(DeniedError):
            self.check(["git", "checkout", "main"])

    def test_cat_is_denied(self):
        with self.assertRaises(DeniedError) as ctx:
            self.check(["cat", "/etc/passwd"])
        self.assertIn("not in the allowlist", str(ctx.exception))

    def test_denial_names_the_alternatives(self):
        with self.assertRaises(DeniedError) as ctx:
            self.check(["nmap", "10.0.0.0/24"])
        self.assertIn("ansible-playbook", str(ctx.exception))

    def test_bare_printenv_is_denied(self):
        # args_allow only constrains the arguments that are present, so without
        # min_args this rule would permit a bare invocation, which dumps the
        # whole child environment instead of naming one variable.
        with self.assertRaises(DeniedError) as ctx:
            self.check(["printenv"])
        self.assertIn("at least 1", str(ctx.exception))

    def test_printenv_takes_exactly_one_variable(self):
        self.check(["printenv", "ROUTER_PW"])
        with self.assertRaises(DeniedError) as ctx:
            self.check(["printenv", "ROUTER_PW", "API_TOKEN"])
        self.assertIn("at most 1", str(ctx.exception))

    def test_printenv_rejects_a_path_argument(self):
        with self.assertRaises(DeniedError):
            self.check(["printenv", "/etc/shadow"])


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
            Config.from_dict({"exec": {"default_cwd": "/home/agent/work/repo"}, "server": {}})
        self.assertIn("[[allow]]", str(ctx.exception))

    def test_bad_regex_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict(
                {"exec": {"default_cwd": "/home/agent/work/repo"},
                 "allow": [{"name": "x", "argv0": "([unclosed"}]})

    def test_rule_without_argv0_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict(
                {"exec": {"default_cwd": "/home/agent/work/repo"},
                 "allow": [{"name": "x"}]})

    def test_empty_command_denied(self):
        config = load_shipped()
        with self.assertRaises(DeniedError):
            authorize([], "/home/agent/work", config.allow, config.exec)


if __name__ == "__main__":
    unittest.main()

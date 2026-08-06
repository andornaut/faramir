"""Turning cmd[0] into the path the executor runs.

There is no allowlist left to test.  What is left is the part that has to be
right for correctness rather than for policy: resolving a name to the file the
child would itself have run, since getting that wrong means running a different
file rather than refusing one.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from faramir.config import Config, ConfigError, ExecConfig  # noqa: E402
from faramir.resolve import ResolveError, resolve_program  # noqa: E402


class TestBareNames(unittest.TestCase):
    """Looked up on the PATH the child will actually get, not the broker's."""

    def test_a_bare_name_resolves_on_the_configured_path(self):
        cfg = ExecConfig(default_cwd="/", base_env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(resolve_program("sh", "/", cfg), os.path.realpath("/bin/sh"))

    def test_the_brokers_own_path_is_not_consulted(self):
        # os.environ["PATH"] almost certainly contains /bin; base_env does not.
        cfg = ExecConfig(default_cwd="/", base_env={"PATH": "/nonexistent"})
        with self.assertRaises(ResolveError) as ctx:
            resolve_program("sh", "/", cfg)
        self.assertIn("not found on the broker's PATH", str(ctx.exception))

    def test_the_error_says_where_to_put_a_venv(self):
        # The one failure an operator will actually hit, so it has to be
        # self-correcting rather than just true.
        cfg = ExecConfig(default_cwd="/", base_env={"PATH": "/nonexistent"})
        with self.assertRaises(ResolveError) as ctx:
            resolve_program("ansible-playbook", "/", cfg)
        message = str(ctx.exception)
        self.assertIn("base_env", message)
        self.assertIn("venv", message)


class TestExplicitPaths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="faramir-resolve-")
        self.script = os.path.join(self.tmp, "deploy.sh")
        with open(self.script, "w") as fh:
            fh.write("#!/bin/sh\n")
        os.chmod(self.script, 0o755)
        self.cfg = ExecConfig(default_cwd=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_an_absolute_path_anywhere_is_fine(self):
        # No allowed_bin_dirs any more: a script in the working tree is exactly
        # the thing an operator wants to run, and it never lived in /usr/bin.
        self.assertEqual(
            resolve_program(self.script, self.tmp, self.cfg), os.path.realpath(self.script)
        )

    def test_a_relative_path_resolves_against_the_request_cwd(self):
        # Not the broker's own working directory: that would silently execute a
        # different file of the same name.
        self.assertEqual(
            resolve_program("./deploy.sh", self.tmp, self.cfg),
            os.path.realpath(self.script),
        )

    def test_a_different_cwd_does_not_find_it(self):
        with self.assertRaises(ResolveError):
            resolve_program("./deploy.sh", "/usr", self.cfg)

    def test_a_missing_program_is_named(self):
        with self.assertRaises(ResolveError) as ctx:
            resolve_program(os.path.join(self.tmp, "nope"), self.tmp, self.cfg)
        self.assertIn("no such program", str(ctx.exception))

    def test_a_non_executable_file_is_refused(self):
        plain = os.path.join(self.tmp, "notes.txt")
        with open(plain, "w") as fh:
            fh.write("hello\n")
        os.chmod(plain, 0o644)
        with self.assertRaises(ResolveError) as ctx:
            resolve_program(plain, self.tmp, self.cfg)
        self.assertIn("not executable", str(ctx.exception))

    def test_symlinks_are_resolved(self):
        link = os.path.join(self.tmp, "link.sh")
        os.symlink(self.script, link)
        self.assertEqual(
            resolve_program(link, self.tmp, self.cfg), os.path.realpath(self.script)
        )

    def test_empty_is_refused(self):
        with self.assertRaises(ResolveError):
            resolve_program("", self.tmp, self.cfg)


class TestTheAllowlistRemoval(unittest.TestCase):
    """Both settings are hard errors, not silently ignored keys.

    A config still carrying them reads as though commands were being
    constrained, which is the one way this change could mislead an operator.
    """

    def base(self, **extra):
        return {"exec": {"default_cwd": "/home/agent/work/repo", **extra}}

    def test_a_leftover_allow_table_is_a_config_error(self):
        with self.assertRaises(ConfigError) as ctx:
            Config.from_dict(
                {**self.base(), "allow": [{"name": "ls", "argv0": "^ls$"}]}, "t"
            )
        self.assertIn("[[allow]]", str(ctx.exception))

    def test_a_leftover_allowed_bin_dirs_is_a_config_error(self):
        with self.assertRaises(ConfigError) as ctx:
            Config.from_dict(self.base(allowed_bin_dirs=["/usr/bin"]), "t")
        message = str(ctx.exception)
        self.assertIn("allowed_bin_dirs", message)
        self.assertIn("base_env", message)

    def test_a_config_with_neither_loads(self):
        config = Config.from_dict(self.base(), "t")
        self.assertEqual(config.exec.default_cwd, "/home/agent/work/repo")


if __name__ == "__main__":
    unittest.main()

"""``sync``'s git plumbing, without a broker.

Separate from ``test_sync`` so it runs anywhere git is installed: the sync
failure these cover is invisible to a single-uid end-to-end test, because it
depends on the source tree having a different owner than the process reading
it.  ``GIT_TEST_ASSUME_DIFFERENT_OWNER`` reproduces that without a second uid.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from secretd.config import SyncConfig  # noqa: E402
from secretd.sync import SyncError, sync  # noqa: E402


def git(cwd, *args):
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
    )
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True)


@unittest.skipUnless(shutil.which("git"), "needs git")
class TestSyncGit(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.source = os.path.join(self.dir, "source")
        self.dest = os.path.join(self.dir, "dest")
        os.makedirs(self.source)
        git(self.source, "init", "-q", "-b", "main")
        self.write("- hosts: all\n")
        git(self.source, "add", "-A")
        git(self.source, "commit", "-qm", "first")
        subprocess.run(
            ["git", "clone", "-q", self.source, self.dest], check=True, capture_output=True
        )
        self.cfg = SyncConfig(
            enabled=True,
            source=self.source,
            dest=self.dest,
            default_ref="main",
            allowed_refs=[re.compile(r"^main$")],
            git=shutil.which("git"),
        )

    def write(self, text):
        with open(os.path.join(self.source, "site.yml"), "w", encoding="utf-8") as fh:
            fh.write(text)

    def commit(self, text, message):
        self.write(text)
        git(self.source, "add", "-A")
        git(self.source, "commit", "-qm", message)

    @staticmethod
    @contextlib.contextmanager
    def assume_different_owner():
        """Make git treat sync's repos as owned by another uid.

        ``_git`` passes a fixed environment, deliberately, so exporting the
        variable into this process would not reach the child.  It has to be
        injected at the subprocess boundary or the test proves nothing.
        """
        real = subprocess.run

        def run(argv, **kwargs):
            env = dict(kwargs.pop("env", None) or os.environ)
            env["GIT_TEST_ASSUME_DIFFERENT_OWNER"] = "1"
            return real(argv, env=env, **kwargs)

        with mock.patch.object(subprocess, "run", run):
            yield

    def test_promotes_the_committed_commit(self):
        self.commit("- hosts: all\n  tasks: []\n", "promoted")
        result = sync(self.cfg, None)
        self.assertEqual(result.subject, "promoted")
        with open(os.path.join(self.dest, "site.yml"), encoding="utf-8") as fh:
            self.assertIn("tasks: []", fh.read())

    def test_source_owned_by_another_uid(self):
        """The broker's uid does not own the agent's tree.

        git calls that dubious ownership and refuses.  The grant has to reach
        the ``upload-pack`` child, which is why it cannot go through
        ``GIT_CONFIG_COUNT``: that is in git's ``local_repo_env`` and is
        stripped on the way.
        """
        self.commit("- hosts: all\n  tasks: []\n", "promoted across uids")
        # Scoped to the sync call: the fixture commits above are the agent's
        # own work, and they do run as the owner of the tree.
        with self.assume_different_owner():
            self.assertEqual(sync(self.cfg, None).subject, "promoted across uids")

    def test_uncommitted_source_changes_are_not_promoted(self):
        self.commit("- hosts: all\n  tasks: []\n", "committed")
        sync(self.cfg, None)
        self.write("- hosts: all\n  tasks: [{debug: {var: vault_password}}]\n")
        sync(self.cfg, None)
        with open(os.path.join(self.dest, "site.yml"), encoding="utf-8") as fh:
            self.assertNotIn("vault_password", fh.read())

    def test_disallowed_ref_is_refused(self):
        with self.assertRaises(SyncError):
            sync(self.cfg, "other")

    def test_ref_may_not_start_with_a_dash(self):
        cfg = SyncConfig(**{**self.cfg.__dict__, "allowed_refs": [re.compile(r".")]})
        with self.assertRaises(SyncError):
            sync(cfg, "--upload-pack=touch /tmp/pwned")

    def test_source_path_containing_a_config_comment_character(self):
        """git-config values stop at '#', so an unquoted grant would truncate.

        The path would then be granted for some shorter prefix and the real one
        still refused, which surfaces as dubious ownership on every sync.
        """
        awkward = os.path.join(self.dir, "re#po; and more")
        shutil.move(self.source, awkward)
        cfg = SyncConfig(**{**self.cfg.__dict__, "source": awkward})
        git(awkward, "config", "user.email", "t@t")
        with self.assume_different_owner():
            self.assertEqual(sync(cfg, None).subject, "first")

    def test_no_temporary_config_is_left_behind(self):
        before = set(os.listdir(tempfile.gettempdir()))
        sync(self.cfg, None)
        leaked = [
            name
            for name in set(os.listdir(tempfile.gettempdir())) - before
            if name.startswith("secretd-sync-")
        ]
        self.assertEqual(leaked, [])


if __name__ == "__main__":
    unittest.main()

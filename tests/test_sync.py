"""Sync mediation: the broker executes committed content, not the editor buffer.

Without this the isolation buys very little -- the agent could write
``debug: var=vault_router_password`` into a playbook and ask the broker to run
it.  Redaction still catches the value, but "the broker runs whatever the agent
just typed" is not a property worth having.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from harness import Broker, have  # noqa: E402


def git(cwd, *args, **kw):
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
    )
    return subprocess.run(
        ["git", *args], cwd=str(cwd), env=env, capture_output=True, text=True, check=True, **kw
    )


@unittest.skipUnless(have("sops", "age-keygen", "git"), "needs sops, age and git")
class TestSync(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = Broker().build()

        # The agent's working tree: where authoring happens.
        agent = cls.broker.agent_tree
        git(agent, "init", "-q", "-b", "main")
        (agent / "site.yml").write_text("- hosts: local\n  tasks: []\n")
        (agent / "inventory.ini").write_text("[local]\nlocalhost ansible_connection=local\n")
        git(agent, "add", "-A")
        git(agent, "commit", "-qm", "initial playbook")

        # The broker's checkout: where execution happens.
        dest = cls.broker.workdir
        git(dest, "init", "-q", "-b", "main")
        (dest / ".gitignore").write_text("group_vars/all/vault.sops.yml\nansible.cfg\n")
        git(dest, "add", "-A")
        git(dest, "commit", "-qm", "bootstrap")

        cls.broker.start()

    @classmethod
    def tearDownClass(cls):
        cls.broker.cleanup()

    def test_sync_promotes_the_committed_commit(self):
        response = self.broker.call({"op": "sync"})
        self.assertIsNone(response.get("error"), response.get("error"))
        head = git(self.broker.agent_tree, "rev-parse", "HEAD").stdout.strip()
        subject = git(self.broker.agent_tree, "log", "-1", "--pretty=%s").stdout.strip()
        self.assertEqual(response["commit"], head)
        self.assertIn(subject, response["output"])

    def test_only_committed_edits_are_promoted(self):
        agent = self.broker.agent_tree
        (agent / "site.yml").write_text("- hosts: local\n  tasks: [] # edited\n")

        self.broker.call({"op": "sync"})
        self.assertNotIn(
            "# edited",
            (self.broker.workdir / "site.yml").read_text(),
            "an uncommitted edit reached the execution checkout",
        )

        git(agent, "add", "-A")
        git(agent, "commit", "-qm", "edit the playbook")
        response = self.broker.call({"op": "sync"})
        self.assertIsNone(response.get("error"), response.get("error"))
        self.assertIn("# edited", (self.broker.workdir / "site.yml").read_text())

    def test_disallowed_ref_is_refused(self):
        response = self.broker.call({"op": "sync", "ref": "--upload-pack=/bin/sh"})
        self.assertEqual(response["error"]["code"], "sync_failed")
        self.assertIn("not permitted", response["error"]["message"])

    def test_sync_is_not_reachable_through_exec(self):
        # git fetch/checkout are explicitly denied by the git-readonly rule.
        response = self.broker.run(["git", "fetch", str(self.broker.agent_tree), "main"])
        self.assertEqual(response["error"]["code"], "denied")

    def test_sync_is_audited(self):
        self.broker.call({"op": "sync"})
        self.assertIn('"op": "sync"', self.broker.raw_log_text())


if __name__ == "__main__":
    unittest.main()

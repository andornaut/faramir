"""The broker's ssh-agent: children authenticate without holding the keys.

Brokered commands run as faramir-exec. Keys that uid can read are keys any
brokered command can copy, and a fleet SSH key is not rotatable the way a
password is. So the broker keeps the files and lends out an agent socket.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from harness import Broker, have  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from faramir.config import SshConfig  # noqa: E402
from faramir.sshagent import SshAgent  # noqa: E402


class TestDisabledByDefault(unittest.TestCase):
    def test_no_keys_means_no_agent_and_no_injection(self):
        agent = SshAgent(SshConfig())
        self.assertFalse(agent.enabled)
        agent.start()  # must be a harmless no-op
        self.assertEqual(agent.env(), {})
        agent.stop()

    def test_a_missing_binary_does_not_raise(self):
        # A broken [ssh] setup must not stop the broker from serving requests
        # that do not need SSH at all.
        with tempfile.TemporaryDirectory() as tmp:
            agent = SshAgent(
                SshConfig(
                    keys=["/nonexistent/key"],
                    ssh_agent="/nonexistent/ssh-agent",
                    agent_socket=os.path.join(tmp, "agent.sock"),
                    exec_group="",
                )
            )
            agent.start()
            self.assertEqual(agent.env(), {})
            agent.stop()


@unittest.skipUnless(
    have("sops", "age-keygen", "ssh-agent", "ssh-add", "ssh-keygen"),
    "needs sops, age and openssh",
)
class TestAgentIsUsableByChildren(unittest.TestCase):
    broker: Broker

    @classmethod
    def setUpClass(cls):
        cls.broker = Broker(ssh_keys=True).build().start()

    @classmethod
    def tearDownClass(cls):
        cls.broker.cleanup()

    def test_children_get_ssh_auth_sock(self):
        response = self.broker.run(["bash", "-lc", 'echo "[${SSH_AUTH_SOCK:-unset}]"'])
        self.assertIn(str(self.broker.ssh_agent_socket), response["output"])

    def test_the_key_is_loaded_and_usable_through_the_agent(self):
        response = self.broker.run(["bash", "-lc", "ssh-add -l"])
        self.assertEqual(response["exit_code"], 0, response["output"])
        self.assertIn("faramir-test", response["output"])

    def test_the_agent_socket_is_not_world_accessible(self):
        mode = os.stat(self.broker.ssh_agent_socket).st_mode & 0o777
        self.assertEqual(mode & 0o007, 0, f"agent socket is {mode:o}")

    def test_the_private_key_never_appears_in_output(self):
        # ssh-add -L prints public keys; the private half must not be
        # obtainable through the agent at all.
        response = self.broker.run(["bash", "-lc", "ssh-add -L"])
        self.assertNotIn("PRIVATE KEY", response["output"])
        self.assertNotIn(
            self.broker.ssh_key.read_text().strip().splitlines()[1],
            response["output"],
        )


@unittest.skipUnless(
    have("sops", "age-keygen", "ssh-agent", "ssh-add", "ssh-keygen"),
    "needs sops, age and openssh",
)
class TestAgentLifetime(unittest.TestCase):
    """Its own broker: this shuts one down, which the other cases still need."""

    def test_the_agent_dies_with_the_broker(self):
        broker = Broker(ssh_keys=True).build().start()
        try:
            self.assertTrue(broker.ssh_agent_socket.exists())
            broker.stop()
            self.assertFalse(
                broker.ssh_agent_socket.exists(),
                "the agent outlived the broker with keys loaded",
            )
        finally:
            broker.cleanup()


if __name__ == "__main__":
    unittest.main()

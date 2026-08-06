"""The broker's entry point and its agent-facing responses.

These run in-process against a stubbed keeper, so the properties that matter
most are checked without sops, age, or a live broker: what --check reports and
exits with, that it leaves a running broker's ssh-agent alone, that a failed
bind does not strand one, and that no agent-facing response names a ref that
was refused at load.
"""

from __future__ import annotations

import io
import json
import os
import signal
import sys
import unittest
from contextlib import redirect_stdout
from tempfile import TemporaryDirectory
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from faramir.config import Config  # noqa: E402
from faramir.server import Server, main  # noqa: E402

STRONG = "hunter2hunter2"
OTHER = "correcthorsebatterystaple"
SHORT = "1234"

CONFIG = """
[exec]
default_cwd = "/home/agent/work/repo"

[[allow]]
name = "ls"
argv0 = '^/bin/ls$'
"""


class MainTestCase(unittest.TestCase):
    def setUp(self):
        # main() installs handlers bound to its Server.  --check returns before
        # it gets that far, but that is statement order, not a guarantee, and a
        # leaked handler points the rest of the suite at a dead Server.
        for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
            self.addCleanup(signal.signal, sig, signal.getsignal(sig))
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config_path = os.path.join(self.tmp.name, "config.toml")
        with open(self.config_path, "w") as fh:
            fh.write(CONFIG)

    def check(self, values, errors=None):
        """Run `--check` with a stubbed keeper: (exit code, parsed report)."""
        out = io.StringIO()
        with mock.patch(
            "faramir.secretstore.fetch_values", return_value=(values, errors or [])
        ), redirect_stdout(out):
            code = main(["-c", self.config_path, "--check"])
        return code, json.loads(out.getvalue())


class TestTheCheckPath(MainTestCase):
    def test_it_prints_one_json_object(self):
        # One object, not JSON followed by a human-readable line: a caller
        # should not have to split the output on a label to parse it.
        code, report = self.check({"good": STRONG})
        self.assertEqual(code, 0)
        self.assertEqual(report["allow_rules"], ["ls"])
        self.assertEqual(report["secrets"]["ref_count"], 1)

    def test_it_names_the_refused_refs_and_the_reason(self):
        _, report = self.check({"good": STRONG, "pin": SHORT})
        self.assertEqual(report["secrets"]["ref_count"], 1)
        self.assertIn("8 characters", report["secrets"]["not_redactable"]["pin"])

    def test_it_exits_non_zero_when_a_ref_was_refused(self):
        # install/20-install-broker.sh gates the install on this: a refused
        # ref is a runtime failure for every command that injects it.
        code, _ = self.check({"good": STRONG, "pin": SHORT})
        self.assertEqual(code, 1)

    def test_a_config_that_does_not_load_exits_two_and_prints_nothing(self):
        with open(self.config_path, "w") as fh:
            fh.write("[[allow]]\nname = 'x'\nnope = 1\n")
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["-c", self.config_path, "--check"])
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")

    def test_it_does_not_start_an_ssh_agent(self):
        # --check is run against a live broker, whose agent socket a second
        # agent would replace and then outlive.
        with mock.patch("faramir.sshagent.SshAgent.start") as start:
            self.check({"good": STRONG})
        start.assert_not_called()


class TestTheServingPath(MainTestCase):
    def test_a_failed_bind_does_not_strand_the_ssh_agent(self):
        # The agent holds the fleet keys on a socket the executor's group can
        # already reach, and nothing kills it when this process dies.
        with mock.patch("faramir.sshagent.SshAgent.start"), mock.patch(
            "faramir.sshagent.SshAgent.stop"
        ) as stop, mock.patch(
            "faramir.server.Server.listen", side_effect=OSError("address in use")
        ), mock.patch(
            "faramir.secretstore.fetch_values", return_value=({"good": STRONG}, [])
        ):
            with self.assertRaises(OSError):
                main(["-c", self.config_path])
        stop.assert_called_once()


class TestAgentFacingResponses(unittest.TestCase):
    def server(self, values):
        config = Config.from_dict(
            {"exec": {"default_cwd": "/home/agent/work/repo"},
             "allow": [{"name": "ls", "argv0": "^/bin/ls$"}]}, "t")
        server = Server(config)
        with mock.patch("faramir.secretstore.fetch_values", return_value=(values, [])):
            server.store.reload()
        return server

    def test_list_secrets_omits_a_refused_ref(self):
        output = self.server({"good": STRONG, "pin": SHORT})._op_list_secrets()["output"]
        self.assertEqual(output, "secret://good\n")

    def test_status_does_not_name_a_refused_ref(self):
        # A refused value is absent from the redactor, so it still arrives in
        # plaintext if a managed host prints it.  Naming it would tell the
        # agent which secret is worth going after.
        output = self.server({"good": STRONG, "pin": SHORT})._op_status()["output"]
        self.assertNotIn("pin", output)
        self.assertNotIn("not_redactable", output)
        self.assertIn('"ref_count": 1', output)

    def test_list_secrets_ends_every_line(self):
        output = self.server({"good": STRONG, "other": OTHER})._op_list_secrets()["output"]
        self.assertEqual(output, "secret://good\nsecret://other\n")

    def test_list_secrets_is_empty_when_nothing_loaded(self):
        self.assertEqual(self.server({})._op_list_secrets()["output"], "")


if __name__ == "__main__":
    unittest.main()

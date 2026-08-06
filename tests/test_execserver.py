"""How the executor wires up a child.

The fork itself is cheap to exercise in-process: build the PTY pair the broker
would build, hand the slave to Executor.run, and read what comes back.  No
sops, no age, no broker.
"""

from __future__ import annotations

import os
import pty
import select
import socket
import sys
import time
import unittest
from tempfile import TemporaryDirectory

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from faramir.config import Config  # noqa: E402
from faramir.execserver import Executor  # noqa: E402

BASH = "/bin/bash"


@unittest.skipUnless(os.path.exists(BASH), "needs /bin/bash")
class ExecutorTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.executor = Executor(
            Config.from_dict({"allow": [{"name": "ls", "argv0": "^/bin/ls$"}]}, "t")
        )

    def run_child(self, argv, timeout_sec=15):
        """Run one command the way the broker would: (response, output)."""
        master, slave = pty.openpty()
        broker, executor = socket.socketpair()
        self.addCleanup(broker.close)
        self.addCleanup(executor.close)
        try:
            response = self.executor.run(
                {"argv": argv, "cwd": self.tmp.name, "timeout_sec": timeout_sec},
                slave,
                executor,
            )
        finally:
            # run() closes the slave once the child holds it, but returns with
            # it still open when it refuses the request.  The connection
            # handler closes it either way, so this stands in for that.
            try:
                os.close(slave)
            except OSError:
                pass
            output = self.drain(master)
        return response, output

    @staticmethod
    def drain(master, timeout=10.0):
        """Read the master until EOF.  Bounded, so a regression fails a test
        rather than hanging the suite."""
        output = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not select.select([master], [], [], 0.2)[0]:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break  # EIO: every slave fd is gone
            if not chunk:
                break
            output += chunk
        os.close(master)
        return output.decode(errors="replace")


class TestStdin(ExecutorTestCase):
    def test_a_child_reading_stdin_gets_eof(self):
        # Nothing ever writes to the master, so a readable stdin would block
        # this child until its timeout while holding a concurrency slot.
        response, output = self.run_child([BASH, "-lc", "read -r x; echo GOT=[$x]"])
        self.assertFalse(response["timed_out"])
        self.assertIn("GOT=[]", output)

    def test_a_bare_shell_exits_instead_of_waiting(self):
        # The bash rule permits zero arguments, which is an interactive shell.
        response, _ = self.run_child([BASH])
        self.assertFalse(response["timed_out"])
        self.assertEqual(response["exit_code"], 0)


class TestTheTerminal(ExecutorTestCase):
    def test_stdout_is_a_terminal(self):
        # A pipe would report "not a tty", and would miss /dev/tty writes.
        _, output = self.run_child([BASH, "-lc", "test -t 1 && echo IS_TTY"])
        self.assertIn("IS_TTY", output)

    def test_writes_to_dev_tty_are_captured(self):
        # ssh and sudo prompt this way, bypassing stdout entirely.  It works
        # only while the child owns the controlling terminal, which it claims
        # through stdout now that stdin is /dev/null.
        _, output = self.run_child([BASH, "-lc", "echo TTY_WRITE > /dev/tty"])
        self.assertIn("TTY_WRITE", output)


class TestRefusals(ExecutorTestCase):
    def test_a_binary_outside_the_allowed_dirs_is_refused(self):
        # Checked here as well as in the broker, so a broker bug cannot become
        # "run anything from anywhere as faramir-exec".
        response, _ = self.run_child([os.path.join(self.tmp.name, "evil")])
        self.assertEqual(response["error"]["code"], "denied")


if __name__ == "__main__":
    unittest.main()

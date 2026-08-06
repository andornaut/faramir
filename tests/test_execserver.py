"""How the executor wires up a child.

The fork itself is cheap to exercise in-process: build the PTY pair the broker
would build, hand the slave to Executor.run, and read the master while the
child runs.  No sops, no age, no broker.
"""

from __future__ import annotations

import os
import pty
import select
import socket
import sys
import threading
import time
import unittest
from tempfile import TemporaryDirectory

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from faramir.config import Config  # noqa: E402
from faramir.executor import _set_winsize  # noqa: E402
from faramir.execserver import Executor  # noqa: E402

BASH = "/bin/bash"


@unittest.skipUnless(os.path.exists(BASH), "needs /bin/bash")
class ExecutorTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Config.from_dict(
            {"exec": {"default_cwd": self.tmp.name},
             }, "t"
        )
        self.executor = Executor(self.config)

    def run_child(self, argv, timeout_sec=15):
        """Run one command the way the broker would: (response, output)."""
        master, slave = pty.openpty()
        _set_winsize(master, self.config.exec.term_rows, self.config.exec.term_cols)
        broker, executor = socket.socketpair()
        self.addCleanup(broker.close)
        self.addCleanup(executor.close)

        # Read while the child runs, which is what the broker does.  The PTY
        # buffer holds about 13 KB; a child that fills it blocks on the write
        # and never reaches its exit, so draining afterwards would deadlock.
        collected: list[str] = []
        reader = threading.Thread(target=lambda: collected.append(self.drain(master)))
        reader.start()

        handed = os.dup(slave)  # the copy run() takes ownership of
        try:
            response = self.executor.run(
                {"argv": argv, "cwd": self.tmp.name, "timeout_sec": timeout_sec},
                handed,
                executor,
            )
            if "error" in response:
                # run() closes the slave only once a child holds it, so a
                # refused request comes back with this one still open.
                os.close(handed)
        finally:
            os.close(slave)  # the last slave fd: now the master can see EOF
            reader.join(timeout=60)
        self.assertFalse(reader.is_alive(), "the PTY never reached EOF")
        return response, collected[0]

    @staticmethod
    def drain(master, timeout=45.0):
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
        response, output = self.run_child([BASH, "-c", "read -r x; echo GOT=[$x]"])
        self.assertFalse(response["timed_out"])
        self.assertIn("GOT=[]", output)

    def test_a_bare_shell_exits_instead_of_waiting(self):
        # A bare shell is an interactive one.  The executor checks nothing
        # about argv, so what stops this hanging is the /dev/null stdin.
        response, _ = self.run_child([BASH])
        self.assertFalse(response["timed_out"])
        self.assertEqual(response["exit_code"], 0)


class TestOutput(ExecutorTestCase):
    def test_a_chatty_child_is_not_blocked_by_a_full_buffer(self):
        # More than the PTY buffer holds, so this only completes if something
        # is reading the master while the child writes.
        response, output = self.run_child(
            [BASH, "-c", "head -c 100000 /dev/zero | tr '\\0' x; echo END"]
        )
        self.assertFalse(response["timed_out"])
        self.assertIn("END", output)
        self.assertGreater(output.count("x"), 99000)


class TestTheTerminal(ExecutorTestCase):
    def test_stdout_is_a_terminal(self):
        # A pipe would report "not a tty", and would miss /dev/tty writes.
        _, output = self.run_child([BASH, "-c", "test -t 1 && echo IS_TTY"])
        self.assertIn("IS_TTY", output)

    def test_writes_to_dev_tty_are_captured(self):
        # ssh and sudo prompt this way, bypassing stdout entirely.  It works
        # only while the child owns the controlling terminal, which it claims
        # through stdout now that stdin is /dev/null.
        _, output = self.run_child([BASH, "-c", "echo TTY_WRITE > /dev/tty"])
        self.assertIn("TTY_WRITE", output)

    def test_the_child_gets_the_configured_window_size(self):
        _, output = self.run_child([BASH, "-c", "stty size < /dev/tty"])
        self.assertIn(
            f"{self.config.exec.term_rows} {self.config.exec.term_cols}", output
        )


class TestRefusals(ExecutorTestCase):
    def test_the_executor_does_not_second_guess_argv0(self):
        """It runs what the broker sends, from wherever the broker says.

        There used to be an allowed_bin_dirs re-check here, justified as
        stopping a broker bug becoming "run anything from anywhere as
        faramir-exec".  It went with the allowlist: it bounded argv[0] only, so
        any request for bash reached past it in one step, and meanwhile it
        refused every venv, shim and working-tree script.  What bounds this uid
        is what it holds -- no key, no audit log, no SSH key -- plus the mode
        on its socket (0660 root:faramir-broker, so the executor's own uid
        cannot connect), which tests/verify.sh checks as 1k on a real
        deployment.

        Asserted the way the documented leaks are: pinned open, so a change
        that reintroduces a check has to revisit this reasoning first.
        """
        script = os.path.join(self.tmp.name, "from-anywhere.sh")
        with open(script, "w") as fh:
            fh.write("#!/bin/sh\necho RAN_FROM_TMP\n")
        os.chmod(script, 0o755)
        response, output = self.run_child([script])
        self.assertIsNone(response.get("error"), response.get("error"))
        self.assertEqual(response["exit_code"], 0)
        self.assertIn("RAN_FROM_TMP", output)

    def test_a_missing_binary_is_an_exec_failure(self):
        response, _ = self.run_child([os.path.join(self.tmp.name, "nope")])
        self.assertEqual(response["error"]["code"], "exec_failed")


if __name__ == "__main__":
    unittest.main()

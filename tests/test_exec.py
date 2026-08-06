"""The executor: forks brokered commands under a uid that holds nothing.

The behaviour worth pinning is what happens when things go wrong. A child that
outlives its broker, or its timeout, is a process holding a credential in its
environment with nobody watching it.
"""

from __future__ import annotations

import os
import pty
import socket
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from harness import Broker, have  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from faramir.execserver import ExecClient, ExecError, _outside_bin_dirs  # noqa: E402
from faramir.config import ExecConfig  # noqa: E402

PW_REF = "secret://home/router/admin"


@unittest.skipUnless(have("sops", "age-keygen"), "needs sops and age")
class ExecTestCase(unittest.TestCase):
    broker: Broker

    @classmethod
    def setUpClass(cls):
        cls.broker = Broker().build().start()

    @classmethod
    def tearDownClass(cls):
        cls.broker.cleanup()

    def client(self) -> ExecClient:
        return ExecClient(str(self.broker.exec_socket_path))


class TestRequestValidation(ExecTestCase):
    def test_a_request_without_a_terminal_fd_is_refused(self):
        response = self.broker.exec_call({"argv": ["/bin/echo", "hi"]})
        self.assertEqual(response["error"]["code"], "bad_request")
        self.assertIn("terminal fd", response["error"]["message"])

    def test_argv_must_be_a_non_empty_list(self):
        for argv in ([], "echo", [1, 2], None):
            with self.subTest(argv=argv):
                response = self.broker.exec_call({"argv": argv})
                self.assertEqual(response["error"]["code"], "bad_request")

    def test_binaries_outside_allowed_bin_dirs_are_refused(self):
        # The broker checks this too.  Repeating it here means a broker bug
        # cannot become "run anything from anywhere as the executor's uid".
        master, slave = pty.openpty()
        client = self.client()
        try:
            client.start(
                argv=[str(self.broker.root / "payload.sh")],
                cwd=str(self.broker.workdir),
                env={},
                timeout_sec=10,
                kill_grace_sec=1,
                slave_fd=slave,
            )
            with self.assertRaises(ExecError) as caught:
                client.result()
            self.assertIn("allowed_bin_dirs", str(caught.exception))
        finally:
            os.close(slave)
            os.close(master)
            client.close()

    def test_bin_dir_check_resolves_symlinks(self):
        cfg = ExecConfig(allowed_bin_dirs=["/usr/bin", "/bin"])
        self.assertIsNone(_outside_bin_dirs("/bin/sh", cfg))
        self.assertIsNotNone(_outside_bin_dirs("/tmp/sh", cfg))


class TestChildLifetime(ExecTestCase):
    def test_a_child_is_killed_when_the_broker_hangs_up(self):
        """An orphan holding a credential in its environ must not survive."""
        master, slave = pty.openpty()
        client = self.client()
        marker = self.broker.root / "still-running"
        try:
            client.start(
                argv=["/bin/sh", "-c", f"touch {marker}; sleep 30"],
                cwd=str(self.broker.workdir),
                env={"PATH": "/usr/bin:/bin"},
                timeout_sec=30,
                kill_grace_sec=1,
                slave_fd=slave,
            )
        finally:
            os.close(slave)
        deadline = time.time() + 10
        while not marker.exists() and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(marker.exists(), "the child never started")

        client.abort()  # hang up, as a dying broker would

        # The PTY master reaching EOF means every copy of the slave is closed,
        # which means the child is gone.
        os.set_blocking(master, False)
        deadline = time.time() + 10
        gone = False
        while time.time() < deadline:
            try:
                if os.read(master, 4096) == b"":
                    gone = True
                    break
            except BlockingIOError:
                time.sleep(0.05)
            except OSError:
                gone = True
                break
        os.close(master)
        self.assertTrue(gone, "the child outlived the broker's connection")

    def test_timeout_is_enforced_by_the_executor(self):
        response = self.broker.run(["bash", "-lc", "sleep 30"], timeout_sec=1)
        self.assertTrue(response["timed_out"], response)
        self.assertIn("timed out", response["output"])
        self.assertLess(response["duration_sec"], 20)

    def test_exit_codes_survive_the_extra_hop(self):
        for code in (0, 1, 7, 42):
            with self.subTest(code=code):
                response = self.broker.run(["bash", "-lc", f"exit {code}"])
                self.assertEqual(response["exit_code"], code)

    def test_a_killed_child_reports_a_signal_exit_code(self):
        response = self.broker.run(["bash", "-lc", "kill -9 $$"])
        self.assertEqual(response["exit_code"], 128 + 9)


class TestSeparation(ExecTestCase):
    def test_the_child_home_is_not_the_brokers(self):
        # The broker used to set HOME from its own passwd entry, which would
        # now point a child at a directory it cannot write.
        response = self.broker.run(["bash", "-lc", "cd $HOME && test -w . && echo ok"])
        self.assertIn("ok", response["output"])

    def test_the_child_does_not_inherit_the_brokers_environment(self):
        response = self.broker.run(
            ["bash", "-lc", 'echo "[${CREDENTIALS_DIRECTORY:-unset}]"']
        )
        self.assertIn("[unset]", response["output"])

    def test_a_pty_is_still_a_tty_after_the_fd_passing(self):
        response = self.broker.run(["bash", "-lc", "test -t 1 && echo tty"])
        self.assertIn("tty", response["output"])

    def test_writes_straight_to_dev_tty_are_still_captured(self):
        response = self.broker.run(
            ["bash", "-lc", "printenv ROUTER_PW > /dev/tty"], {"ROUTER_PW": PW_REF}
        )
        self.assertIn("«SECRET:home/router/admin»", response["output"])


class TestUnavailableExecutor(unittest.TestCase):
    def test_a_missing_socket_is_a_clear_error(self):
        client = ExecClient("/nonexistent/exec.sock")
        master, slave = pty.openpty()
        try:
            with self.assertRaises(ExecError) as caught:
                client.start(
                    argv=["/bin/true"],
                    cwd="/",
                    env={},
                    timeout_sec=5,
                    kill_grace_sec=1,
                    slave_fd=slave,
                )
            self.assertIn("executor socket", str(caught.exception))
        finally:
            os.close(slave)
            os.close(master)

    def test_result_without_a_command_in_flight(self):
        with self.assertRaises(ExecError):
            ExecClient("/nonexistent/exec.sock").result()


if __name__ == "__main__":
    unittest.main()

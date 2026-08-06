"""End-to-end tests against a running broker.

This is the Phase 7 verification matrix from the plan, executed against a real
faramir with a real age key and real sops-encrypted secrets.  The two tests at
the bottom assert that the *documented leaks* still leak: if someone
accidentally "fixes" them, the README would start promising a property the
system does not have.
"""

from __future__ import annotations

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from harness import API_TOKEN, ROUTER_PW, SHORT_PW, Broker, have  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from faramir.redact import token_for  # noqa: E402

ROUTER_TOKEN = token_for("home/router/admin")
PW_REF = "secret://home/router/admin"


@unittest.skipUnless(have("sops", "age-keygen"), "needs sops and age")
class BrokerTestCase(unittest.TestCase):
    broker: Broker

    @classmethod
    def setUpClass(cls):
        cls.broker = Broker().build().start()

    @classmethod
    def tearDownClass(cls):
        cls.broker.cleanup()

    def assertNoPlaintext(self, text: str, *, secret: str = ROUTER_PW):
        self.assertNotIn(secret, text, "PLAINTEXT SECRET REACHED THE CLIENT")


class TestSecretResolution(BrokerTestCase):
    def test_status_reports_loaded_secrets(self):
        response = self.broker.call({"op": "status"})
        self.assertIn('"ref_count": 3', response["output"])
        self.assertIn("vault.sops.yml", response["output"])
        self.assertNoPlaintext(response["output"])

    def test_list_secrets_returns_names_only(self):
        response = self.broker.call({"op": "list_secrets"})
        self.assertIn("secret://home/router/admin", response["output"])
        self.assertIn("secret://home/api/token", response["output"])
        self.assertNoPlaintext(response["output"])
        self.assertNoPlaintext(response["output"], secret=API_TOKEN)

    def test_a_value_the_redactor_cannot_cover_is_not_loaded(self):
        listed = self.broker.call({"op": "list_secrets"})
        self.assertNotIn("short_pin", listed["output"])
        _, report = self.broker.store_check()
        self.assertIn("short_pin", report["secrets"]["not_redactable"])

    def test_the_refused_refs_are_not_named_to_the_agent(self):
        # A refused value is absent from the redactor, so it arrives in
        # plaintext if a managed host prints it.  Naming it would tell the
        # agent exactly which secret that is.
        for op in ("list_secrets", "status"):
            with self.subTest(op=op):
                response = self.broker.call({"op": op})
                self.assertNotIn("not_redactable", response["output"])
                self.assertNotIn("short_pin", response["output"])

    def test_check_fails_when_a_ref_was_refused(self):
        # install/20-install-broker.sh gates the install on this exit code.
        code, _ = self.broker.store_check()
        self.assertEqual(code, 1)

    def test_a_refused_ref_cannot_be_injected(self):
        # And the error says why, so the operator is not sent looking for a
        # typo in a ref that is spelled correctly.
        response = self.broker.run(["printenv", "X"], {"X": "secret://short_pin"})
        self.assertEqual(response["error"]["code"], "unknown_secret")
        self.assertIn("refused at load", response["error"]["message"])

    def test_unknown_ref_is_an_error(self):
        response = self.broker.run(["printenv", "X"], {"X": "secret://nope/nothing"})
        self.assertEqual(response["error"]["code"], "unknown_secret")

    def test_literal_value_cannot_be_passed_as_a_ref(self):
        # There is no way to hand the broker a value: env_refs are names only.
        response = self.broker.run(["printenv", "X"], {"X": "hunter2"})
        self.assertEqual(response["error"]["code"], "bad_request")
        self.assertIn("secret://", response["error"]["message"])


class TestVerificationMatrix(BrokerTestCase):
    """Numbered to match the table in the README."""

    def test_03_printenv_shows_a_token_not_a_value(self):
        response = self.broker.run(["printenv", "ROUTER_PW"], {"ROUTER_PW": PW_REF})
        self.assertEqual(response["exit_code"], 0)
        self.assertNoPlaintext(response["output"])
        self.assertIn(ROUTER_TOKEN, response["output"])
        self.assertEqual(
            [r for r in response["redactions"] if r["token"] == ROUTER_TOKEN][0]["count"], 1
        )

    def test_04_base64_wrapped_is_redacted(self):
        response = self.broker.run(
            ["bash", "-lc", "printenv ROUTER_PW | base64"], {"ROUTER_PW": PW_REF}
        )
        self.assertNoPlaintext(response["output"])
        self.assertNoPlaintext(response["output"], secret=base64.b64encode(ROUTER_PW.encode()).decode())
        self.assertIn(ROUTER_TOKEN, response["output"])

    def test_05_base64_unwrapped_is_redacted(self):
        response = self.broker.run(
            ["bash", "-lc", "printenv ROUTER_PW | base64 -w0"], {"ROUTER_PW": PW_REF}
        )
        self.assertNoPlaintext(response["output"])
        self.assertIn(ROUTER_TOKEN, response["output"])

    @unittest.skipUnless(have("ansible-playbook"), "needs ansible-core")
    def test_06_ansible_playbook_vvv_has_no_plaintext(self):
        response = self.broker.run(
            ["ansible-playbook", "-i", "inventory.ini", "site.yml", "-vvv"],
            {"ROUTER_PW": PW_REF},
        )
        self.assertNoPlaintext(response["output"])
        self.assertIn("PLAY RECAP", response["output"])

    @unittest.skipUnless(have("ansible-playbook"), "needs ansible-core")
    def test_07_playbook_that_prints_a_vault_var_is_redacted(self):
        response = self.broker.run(
            ["ansible-playbook", "-i", "inventory.ini", "site.yml"],
            {"ROUTER_PW": PW_REF},
        )
        self.assertEqual(response["exit_code"], 0, response["output"])
        self.assertNoPlaintext(response["output"])
        self.assertIn(ROUTER_TOKEN, response["output"])
        # ...and it really did run the task, rather than failing early.
        self.assertIn("print the vault variable", response["output"])

    @unittest.skipUnless(have("ansible-playbook"), "needs ansible-core")
    def test_07b_playbook_cannot_decrypt_the_sops_file_itself(self):
        # The arrangement this replaced: Ansible resolving sops vars at run
        # time.  It needed the age key, and nothing gets the age key now.
        response = self.broker.run(
            ["ansible-playbook", "-i", "inventory.ini", "decrypt.yml"]
        )
        self.assertNotEqual(response["exit_code"], 0, response["output"])
        self.assertNoPlaintext(response["output"])

    def test_08_an_unknown_program_is_refused_with_a_usable_message(self):
        # There is no allowlist to refuse this; what refuses it is that the
        # name is not on the PATH the child would get.  The message has to say
        # where to fix that, because it is the failure an operator will hit
        # when a tool lives in a venv or a pipx install.
        response = self.broker.run(["definitely-not-installed-xyzzy"])
        self.assertEqual(response["error"]["code"], "exec_failed")
        self.assertIn("base_env", response["error"]["message"])
        self.assertEqual(response["output"], "")

    def test_09_raw_log_contains_the_plaintext(self):
        response = self.broker.run(["printenv", "ROUTER_PW"], {"ROUTER_PW": PW_REF})
        raw = self.broker.raw_log_text()
        self.assertIn(ROUTER_PW, raw, "the operator's audit log must be usable")
        self.assertIn(response["log_id"], raw)

    def test_09b_raw_log_is_not_group_or_world_readable(self):
        mode = os.stat(self.broker.raw_log).st_mode & 0o777
        self.assertEqual(mode, 0o600, f"raw log mode is {mode:o}")

    # -- documented leaks: these MUST keep leaking ------------------------

    def test_10_reversed_secret_leaks_as_documented(self):
        response = self.broker.run(
            ["bash", "-lc", "printenv ROUTER_PW | rev"], {"ROUTER_PW": PW_REF}
        )
        self.assertIn(
            ROUTER_PW[::-1],
            response["output"],
            "test 10 no longer leaks -- the README's threat model is now wrong",
        )

    def test_11_partial_secret_leaks_as_documented(self):
        response = self.broker.run(
            ["bash", "-lc", "printenv ROUTER_PW | cut -c1-4"], {"ROUTER_PW": PW_REF}
        )
        self.assertIn(ROUTER_PW[:4], response["output"])


class TestNonInjectedSecrets(BrokerTestCase):
    """The requirement off-the-shelf injectors cannot meet."""

    def test_secret_never_injected_is_still_redacted(self):
        # API_TOKEN is not in env_refs and not in this command's environment;
        # it is redacted because the broker knows the whole value set.
        response = self.broker.run(["bash", "-lc", f"echo 'found {API_TOKEN} in a log'"])
        self.assertNoPlaintext(response["output"], secret=API_TOKEN)
        self.assertIn(token_for("home/api/token"), response["output"])

    def test_bash_does_not_receive_the_age_key(self):
        response = self.broker.run(["bash", "-lc", "echo \"[${SOPS_AGE_KEY:-unset}]\""])
        self.assertIn("[unset]", response["output"])

    def test_the_age_key_is_not_in_the_brokers_value_set(self):
        # It used to be, so that a child which printed it got a token instead.
        # Now no child can obtain it, so the property holds by construction and
        # the key is not among the values the broker holds.  Asserting the old
        # behaviour here would hide a regression where the broker starts
        # loading the key again.
        response = self.broker.call({"op": "list_secrets"})
        self.assertNotIn("age-key", response["output"])
        self.assertNotIn("age", [r.split("/")[0] for r in response["refs"]])

    def test_short_secret_is_not_redacted_and_that_is_deliberate(self):
        response = self.broker.run(["bash", "-lc", f"echo 'pin {SHORT_PW} here'"])
        self.assertIn(SHORT_PW, response["output"])


class TestExecutionSemantics(BrokerTestCase):
    def test_exit_code_is_propagated(self):
        self.assertEqual(self.broker.run(["bash", "-lc", "exit 42"])["exit_code"], 42)

    def test_stderr_is_merged(self):
        response = self.broker.run(["bash", "-lc", "echo out; echo err >&2"])
        self.assertIn("out", response["output"])
        self.assertIn("err", response["output"])

    def test_child_sees_a_tty(self):
        # A pipe would report "not a tty" -- and would miss /dev/tty writes.
        response = self.broker.run(["bash", "-lc", "test -t 1 && echo IS_TTY"])
        self.assertIn("IS_TTY", response["output"])

    def test_a_child_reading_stdin_gets_eof_rather_than_blocking(self):
        # Nothing writes to the master, so a readable stdin would hold a
        # concurrency slot until the timeout: a password prompt, or `bash`
        # with no arguments.
        response = self.broker.run(["bash", "-lc", "read -r x; echo GOT=[$x]"], timeout_sec=15)
        self.assertFalse(response["timed_out"])
        self.assertIn("GOT=[]", response["output"])

    def test_a_bare_shell_exits_instead_of_waiting(self):
        response = self.broker.run(["bash"], timeout_sec=15)
        self.assertFalse(response["timed_out"])
        self.assertEqual(response["exit_code"], 0)

    def test_writes_to_dev_tty_are_captured_and_redacted(self):
        # This is the case a pipe cannot catch: ssh and sudo prompt this way.
        response = self.broker.run(
            ["bash", "-lc", 'printenv ROUTER_PW > /dev/tty'], {"ROUTER_PW": PW_REF}
        )
        self.assertNoPlaintext(response["output"])
        self.assertIn(ROUTER_TOKEN, response["output"])

    def test_ansi_is_stripped(self):
        response = self.broker.run(["bash", "-lc", "printf '\\033[31mred\\033[0m\\n'"])
        self.assertNotIn("\x1b", response["output"])
        self.assertIn("red", response["output"])

    def test_timeout_kills_the_child(self):
        response = self.broker.run(["bash", "-lc", "sleep 30"], timeout_sec=2)
        self.assertTrue(response["timed_out"])
        self.assertLess(response["duration_sec"], 20)

    def test_output_is_truncated_not_unbounded(self):
        response = self.broker.run(
            ["bash", "-lc", "head -c 4000000 /dev/zero | tr '\\0' 'a'"], timeout_sec=60
        )
        self.assertTrue(response["truncated"])
        self.assertLess(len(response["output"]), 1_200_000)

    def test_secret_is_not_visible_in_the_process_table(self):
        # Values go in the environment, never in argv, so ps cannot show them.
        response = self.broker.run(
            ["bash", "-lc", "ps -eo args | grep -c Tr0ub4dor || true"], {"X": PW_REF}
        )
        self.assertNoPlaintext(response["output"])

    def test_inline_token_becomes_a_variable_reference(self):
        response = self.broker.run(
            ["bash", "-lc", "echo \"pw={{SECRET:home/router/admin}}\""]
        )
        # The shell expanded the injected variable, and the redactor caught it.
        self.assertNoPlaintext(response["output"])
        self.assertIn(ROUTER_TOKEN, response["output"])

    def test_broker_environment_is_not_inherited(self):
        response = self.broker.run(["bash", "-lc", "echo \"[${CREDENTIALS_DIRECTORY:-unset}]\""])
        self.assertIn("[unset]", response["output"])


class TestClientInterfaces(BrokerTestCase):
    def test_cli_prints_redacted_output_and_exit_code(self):
        result = self.broker.cli(
            ["run", "--env", f"ROUTER_PW={PW_REF}", "--", "printenv", "ROUTER_PW"]
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(ROUTER_TOKEN, result.stdout)
        self.assertNoPlaintext(result.stdout)
        self.assertIn("redacted", result.stderr)

    def test_cli_refuses_a_literal_value(self):
        result = self.broker.cli(["run", "--env", "PW=hunter2", "--", "printenv", "PW"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must reference secret://", result.stderr)

    def test_cli_propagates_exit_code(self):
        self.assertEqual(
            self.broker.cli(["run", "--", "bash", "-lc", "exit 7"]).returncode, 7
        )

    def test_cli_reports_failures_clearly(self):
        result = self.broker.cli(["run", "--", "definitely-not-installed-xyzzy"])
        self.assertIn("exec_failed", result.stderr)

    def test_cli_subcommands_reach_the_broker(self):
        listed = self.broker.cli(["list-secrets"])
        self.assertEqual(listed.returncode, 0)
        self.assertIn(PW_REF, listed.stdout)
        self.assertNoPlaintext(listed.stdout)
        self.assertEqual(self.broker.cli(["status"]).returncode, 0)

    def test_cli_without_a_subcommand_is_a_usage_error(self):
        self.assertEqual(self.broker.cli([]).returncode, 2)

    def test_mcp_lists_tools(self):
        responses = self.broker.mcp(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            ]
        )
        names = {t["name"] for t in responses[1]["result"]["tools"]}
        self.assertEqual(
            names, {"faramir_run", "faramir_list_secrets", "faramir_status"}
        )

    def test_mcp_faramir_run_redacts(self):
        responses = self.broker.mcp(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "faramir_run",
                        "arguments": {
                            "cmd": ["printenv", "ROUTER_PW"],
                            "env_refs": {"ROUTER_PW": PW_REF},
                        },
                    },
                },
            ]
        )
        text = responses[1]["result"]["content"][0]["text"]
        self.assertIn(ROUTER_TOKEN, text)
        self.assertNoPlaintext(text)

    def test_mcp_reports_failures_as_tool_errors(self):
        responses = self.broker.mcp(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "faramir_run",
                               "arguments": {"cmd": ["definitely-not-installed-xyzzy"]}},
                },
            ]
        )
        self.assertTrue(responses[1]["result"]["isError"])

    def test_mcp_list_secrets_shows_no_values(self):
        responses = self.broker.mcp(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "faramir_list_secrets", "arguments": {}},
                },
            ]
        )
        text = responses[1]["result"]["content"][0]["text"]
        self.assertIn("secret://home/router/admin", text)
        self.assertNoPlaintext(text)


class TestProtocolHardening(BrokerTestCase):
    def test_shell_string_is_rejected(self):
        response = self.broker.call({"op": "exec", "cmd": "echo hi | tee /tmp/x"})
        self.assertEqual(response["error"]["code"], "bad_request")

    def test_reserved_env_name_rejected(self):
        response = self.broker.run(["printenv", "X"], {"LD_PRELOAD": PW_REF})
        self.assertEqual(response["error"]["code"], "bad_request")

    def test_age_key_env_cannot_be_overridden(self):
        response = self.broker.run(["printenv", "X"], {"SOPS_AGE_KEY": PW_REF})
        self.assertEqual(response["error"]["code"], "bad_request")

    def test_a_cwd_that_does_not_exist_is_refused(self):
        response = self.broker.run(["bash", "-lc", "true"], cwd="/no/such/dir")
        self.assertEqual(response["error"]["code"], "bad_request")

    def test_garbage_does_not_kill_the_broker(self):
        import socket as _socket

        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as sock:
            sock.connect(str(self.broker.socket_path))
            sock.sendall(b"this is not json\n")
            sock.recv(4096)
        self.assertEqual(self.broker.run(["bash", "-lc", "echo alive"])["exit_code"], 0)

    def test_failures_are_audited(self):
        # A command that never started is still a request the operator should
        # be able to see in the log.
        self.broker.run(["definitely-not-installed-xyzzy"])
        self.assertIn("definitely-not-installed-xyzzy", self.broker.raw_log_text())


if __name__ == "__main__":
    unittest.main()

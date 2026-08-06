"""The store's load-time gate.

A value the redactor cannot cover must not be held: serving it would put it in
a child's environment with nothing to catch it on the way out.  These run
in-process against a stubbed keeper, so they do not need sops or age.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from faramir.config import KeeperConfig, SecretsConfig  # noqa: E402
from faramir.secretstore import SecretError, SecretStore  # noqa: E402

STRONG = "hunter2hunter2hunter2"
SHORT = "1234"
LOW_ENTROPY = "aaaaaaaaaaaaaaaa"


def store(values, errors=None):
    s = SecretStore(SecretsConfig(), KeeperConfig())
    with mock.patch(
        "faramir.secretstore.fetch_values", return_value=(values, errors or [])
    ):
        s.reload()
    return s


class TestTheLoadGate(unittest.TestCase):
    def test_a_redactable_value_is_loaded(self):
        s = store({"good": STRONG})
        self.assertEqual(s.refs(), ["good"])
        self.assertEqual(s.value("good"), STRONG)

    def test_a_short_value_is_refused(self):
        s = store({"good": STRONG, "pin": SHORT})
        self.assertEqual(s.refs(), ["good"])
        self.assertNotIn(SHORT, [v for _, v in s.pairs()])

    def test_a_low_entropy_value_is_refused(self):
        self.assertEqual(store({"dull": LOW_ENTROPY}).refs(), [])

    def test_a_refused_ref_is_not_injectable(self):
        with self.assertRaises(SecretError) as caught:
            store({"pin": SHORT}).value("pin")
        message = str(caught.exception)
        self.assertIn("refused at load", message)
        self.assertIn("8 characters", message)

    def test_an_unknown_ref_is_not_reported_as_refused(self):
        # The two need different messages: one is a typo, the other is a value
        # that has to be lengthened.
        with self.assertRaises(SecretError) as caught:
            store({"good": STRONG}).value("nope")
        self.assertIn("unknown secret ref", str(caught.exception))

    def test_the_agent_facing_summary_does_not_name_them(self):
        # A refused value is still unredacted if it reaches the output some
        # other way, so the list is targeting information, not just a warning.
        described = store({"good": STRONG, "pin": SHORT}).describe()
        self.assertEqual(described["ref_count"], 1)
        self.assertNotIn("not_redactable", described)
        self.assertNotIn("pin", str(described))

    def test_the_operator_summary_names_them_and_the_reason(self):
        described = store({"good": STRONG, "pin": SHORT}).describe_for_operator()
        self.assertEqual(described["ref_count"], 1)
        self.assertIn("8 characters", described["not_redactable"]["pin"])

    def test_a_refusal_does_not_survive_a_reload_that_fixes_it(self):
        s = store({"pin": SHORT})
        self.assertEqual(
            s.describe_for_operator()["not_redactable"],
            {"pin": "shorter than 8 characters"},
        )
        with mock.patch(
            "faramir.secretstore.fetch_values", return_value=({"pin": STRONG}, [])
        ):
            s.reload()
        self.assertEqual(s.describe_for_operator()["not_redactable"], {})
        self.assertEqual(s.refs(), ["pin"])


if __name__ == "__main__":
    unittest.main()

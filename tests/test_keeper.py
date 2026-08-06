"""The keeper: serves values, never key material.

The single property worth protecting here is that no request shape gets the
age key back out.  Everything else in this file exists so that a change which
quietly reintroduces one is caught.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from harness import API_TOKEN, ROUTER_PW, Broker, have  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from faramir.keeper import KeyHolder, flatten  # noqa: E402
from faramir.config import KeeperConfig  # noqa: E402


@unittest.skipUnless(have("sops", "age-keygen"), "needs sops and age")
class KeeperTestCase(unittest.TestCase):
    broker: Broker

    @classmethod
    def setUpClass(cls):
        cls.broker = Broker().build().start()

    @classmethod
    def tearDownClass(cls):
        cls.broker.cleanup()


class TestGetValues(KeeperTestCase):
    def test_serves_every_managed_value(self):
        response = self.broker.keeper_call({"op": "get_values"})
        self.assertEqual(response.get("errors"), [])
        values = response["values"]
        self.assertEqual(values["home/router/admin"], ROUTER_PW)
        self.assertEqual(values["home/api/token"], API_TOKEN)

    def test_refs_filter_is_honoured(self):
        response = self.broker.keeper_call(
            {"op": "get_values", "refs": ["home/api/token"]}
        )
        self.assertEqual(list(response["values"]), ["home/api/token"])

    def test_unknown_ref_in_the_filter_is_simply_absent(self):
        response = self.broker.keeper_call({"op": "get_values", "refs": ["nope/nope"]})
        self.assertEqual(response["values"], {})

    def test_bad_refs_type_is_rejected(self):
        response = self.broker.keeper_call({"op": "get_values", "refs": "home/api/token"})
        self.assertEqual(response["error"]["code"], "bad_request")


class TestTheKeyIsNotObtainable(KeeperTestCase):
    """No request shape returns the age key."""

    def test_no_op_returns_key_material(self):
        for request in (
            {"op": "get_age_key"},
            {"op": "get_key"},
            {"op": "age_key"},
            {"op": "status"},
            {"op": "exec", "cmd": ["cat", "/etc/faramir/age.key"]},
        ):
            with self.subTest(request=request):
                response = self.broker.keeper_call(request)
                self.assertEqual(response["error"]["code"], "unsupported")
                self.assertNotIn(self.broker.age_private, str(response))

    def test_the_refusal_says_why(self):
        response = self.broker.keeper_call({"op": "get_age_key"})
        self.assertIn("no operation that returns key material", response["error"]["message"])

    def test_the_key_is_not_smuggled_out_as_a_value(self):
        response = self.broker.keeper_call({"op": "get_values"})
        self.assertNotIn(self.broker.age_private, str(response["values"]))

    def test_a_malformed_request_does_not_leak(self):
        response = self.broker.keeper_call({"nonsense": True})
        self.assertIn("error", response)
        self.assertNotIn(self.broker.age_private, str(response))


class TestScrubbing(unittest.TestCase):
    """Error strings are the one thing that crosses back to the broker."""

    def _holder(self, key: str) -> KeyHolder:
        holder = KeyHolder(KeeperConfig())
        holder._key = key
        return holder

    def test_key_lines_are_removed_from_error_text(self):
        key = "# created: 2026-01-01\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n"
        holder = self._holder(key)
        scrubbed = holder.scrub(
            "sops failed: could not use AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
        )
        self.assertNotIn("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQ", scrubbed)
        self.assertIn("«AGE-KEY»", scrubbed)

    def test_comment_lines_are_not_treated_as_key_material(self):
        # Scrubbing the comment would blank ordinary words out of error text.
        holder = self._holder("# public key: age1abcdefghijklmnop\nAGE-SECRET-KEY-1ZZZZZZZZZZZZZZZZZZZZZ\n")
        self.assertEqual(holder.scrub("age1abcdefghijklmnop"), "age1abcdefghijklmnop")

    def test_no_key_loaded_is_a_no_op(self):
        holder = KeyHolder(KeeperConfig())
        self.assertEqual(holder.scrub("anything"), "anything")


class TestFlatten(unittest.TestCase):
    def test_only_the_top_level_sops_block_is_dropped(self):
        tree = {"sops": {"age": []}, "vault": {"sops": "a-real-secret"}}
        self.assertEqual(list(flatten(tree)), [("vault/sops", "a-real-secret")])

    def test_booleans_and_nulls_are_not_values(self):
        self.assertEqual(list(flatten({"a": True, "b": None})), [])


if __name__ == "__main__":
    unittest.main()

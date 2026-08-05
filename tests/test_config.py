"""Config parsing.

A config error has to arrive as a ConfigError naming the key, because that is
the only thing ``secretd --check`` can turn into a useful message.  A traceback
tells the operator nothing about which line to fix.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from secretd.config import Config, ConfigError  # noqa: E402

MINIMAL_ALLOW = [{"name": "ls", "argv0": r"^/bin/ls$"}]


def load(**sections):
    return Config.from_dict({"allow": MINIMAL_ALLOW, **sections}, "test.toml")


class TestUnknownKeys(unittest.TestCase):
    SECTIONS = ["server", "exec", "secrets", "audit", "sync"]

    def test_typo_is_a_config_error(self):
        for section in self.SECTIONS:
            with self.subTest(section=section):
                with self.assertRaises(ConfigError) as caught:
                    load(**{section: {"no_such_key": 1}})
                self.assertIn("no_such_key", str(caught.exception))
                self.assertIn(section, str(caught.exception))

    def test_message_lists_the_valid_keys(self):
        with self.assertRaises(ConfigError) as caught:
            load(server={"sockt_path": "/run/x"})
        self.assertIn("socket_path", str(caught.exception))

    def test_scalar_where_a_table_belongs(self):
        """`server = "0660"` instead of `[server]` must not traceback."""
        for section in self.SECTIONS:
            with self.subTest(section=section):
                with self.assertRaises(ConfigError):
                    load(**{section: "0660"})

    def test_allow_must_be_a_list_of_tables(self):
        for value in ["ls", [1, 2], {"name": "ls"}]:
            with self.subTest(value=value):
                with self.assertRaises(ConfigError):
                    Config.from_dict({"allow": value}, "test.toml")


class TestSocketMode(unittest.TestCase):
    def test_octal_string(self):
        self.assertEqual(load(server={"socket_mode": "0660"}).server.socket_mode, 0o660)

    def test_toml_octal_literal_is_already_an_int(self):
        """TOML parses 0o660 to 432; re-reading that as octal would give 0o432,
        which grants write to others and denies read to the devwork group."""
        self.assertEqual(load(server={"socket_mode": 0o660}).server.socket_mode, 0o660)

    def test_unquoted_decimal_is_rejected(self):
        """660 is a plausible typo for 0o660 and would otherwise mean 0o1224."""
        with self.assertRaises(ConfigError) as caught:
            load(server={"socket_mode": 660})
        self.assertIn("range", str(caught.exception))

    def test_garbage_is_a_config_error(self):
        for value in ["09", "rw-rw----", True, 1.5, -1, 0o7777]:
            with self.subTest(value=value):
                with self.assertRaises(ConfigError):
                    load(server={"socket_mode": value})

    def test_default(self):
        self.assertEqual(load().server.socket_mode, 0o660)


class TestAllowRules(unittest.TestCase):
    def test_empty_allowlist_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict({"allow": []}, "test.toml")

    def test_bad_regex_names_the_rule(self):
        with self.assertRaises(ConfigError) as caught:
            Config.from_dict({"allow": [{"name": "oops", "argv0": "("}]}, "test.toml")
        self.assertIn("oops", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

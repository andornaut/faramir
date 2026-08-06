"""Config parsing.

A config error has to arrive as a ConfigError naming the key, because that is
the only thing ``faramir-broker --check`` can turn into a useful message.  A traceback
tells the operator nothing about which line to fix.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from faramir.config import Config, ConfigError  # noqa: E402

MINIMAL_ALLOW = [{"name": "ls", "argv0": r"^/bin/ls$"}]


def load(**sections):
    return Config.from_dict({"allow": MINIMAL_ALLOW, **sections}, "test.toml")


class TestUnknownKeys(unittest.TestCase):
    SECTIONS = ["server", "keeper", "executor", "exec", "secrets", "audit", "sync"]

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

    def test_the_error_never_guesses_the_spelling(self):
        """tomllib parses 0o1000 and 512 to the same int.

        Any advice naming a specific replacement value is wrong for one of the
        spellings, so the message names the accepted forms instead.
        """
        for value in [660, 0o1000, "1000", 4095]:
            with self.subTest(value=value):
                with self.assertRaises(ConfigError) as caught:
                    load(server={"socket_mode": value})
                message = str(caught.exception)
                self.assertIn('"0660" or 0o660', message)
                self.assertNotIn("looks like decimal", message)

    def test_garbage_is_a_config_error(self):
        for value in ["09", "rw-rw----", True, 1.5, -1, 0o7777]:
            with self.subTest(value=value):
                with self.assertRaises(ConfigError):
                    load(server={"socket_mode": value})

    def test_default(self):
        self.assertEqual(load().server.socket_mode, 0o660)


class TestTheAgeKeyMigration(unittest.TestCase):
    """The broker no longer reads the key, so the old settings must not be
    ignored: silently dropping them leaves a config that reads as though
    Ansible were still being handed the master key."""

    def test_provide_age_key_names_the_rule_and_says_what_to_do(self):
        with self.assertRaises(ConfigError) as caught:
            Config.from_dict(
                {"allow": [{"name": "ansible", "argv0": "^ansible$", "provide_age_key": True}]},
                "test.toml",
            )
        message = str(caught.exception)
        self.assertIn("ansible", message)
        self.assertIn("provide_age_key", message)
        self.assertIn("keeper", message)

    def test_age_key_settings_under_secrets_point_at_the_keeper(self):
        for key in ("age_key_credential", "age_key_file"):
            with self.subTest(key=key):
                with self.assertRaises(ConfigError) as caught:
                    load(secrets={key: "age_key"})
                self.assertIn(key, str(caught.exception))
                self.assertIn("[keeper]", str(caught.exception))

    def test_the_keeper_section_parses(self):
        config = load(
            keeper={"socket_path": "/run/x/k.sock", "allowed_users": ["b"], "socket_mode": "0600"}
        )
        self.assertEqual(config.keeper.socket_path, "/run/x/k.sock")
        self.assertEqual(config.keeper.allowed_users, ["b"])
        self.assertEqual(config.keeper.socket_mode, 0o600)

    def test_the_keeper_has_defaults(self):
        self.assertEqual(load().keeper.allowed_users, ["faramir-broker"])


class TestExecutorSection(unittest.TestCase):
    def test_it_parses(self):
        config = load(
            executor={"socket_path": "/run/x/e.sock", "socket_mode": "0600",
                      "allowed_users": ["b"], "max_concurrency": 2}
        )
        self.assertEqual(config.executor.socket_path, "/run/x/e.sock")
        self.assertEqual(config.executor.socket_mode, 0o600)
        self.assertEqual(config.executor.max_concurrency, 2)

    def test_only_the_broker_is_allowed_by_default(self):
        self.assertEqual(load().executor.allowed_users, ["faramir-broker"])

    def test_a_bad_socket_mode_names_the_section(self):
        with self.assertRaises(ConfigError) as caught:
            load(executor={"socket_mode": 660})
        self.assertIn("executor.socket_mode", str(caught.exception))


class TestAllowRules(unittest.TestCase):
    def test_empty_allowlist_is_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict({"allow": []}, "test.toml")

    def test_bad_regex_names_the_rule(self):
        with self.assertRaises(ConfigError) as caught:
            Config.from_dict({"allow": [{"name": "oops", "argv0": "("}]}, "test.toml")
        self.assertIn("oops", str(caught.exception))

    def test_non_string_argv0_is_a_config_error(self):
        for value in [5, ["^/bin/ls$"], None]:
            with self.subTest(value=value):
                with self.assertRaises(ConfigError):
                    Config.from_dict({"allow": [{"name": "x", "argv0": value}]}, "t")

    def test_max_timeout_must_be_a_positive_int(self):
        for value in ["600", 0, -1, 1.5, True]:
            with self.subTest(value=value):
                with self.assertRaises(ConfigError):
                    load(allow=[{**MINIMAL_ALLOW[0], "max_timeout_sec": value}])
        self.assertEqual(
            load(allow=[{**MINIMAL_ALLOW[0], "max_timeout_sec": 60}])
            .allow[0]
            .max_timeout_sec,
            60,
        )


class TestArgumentCounts(unittest.TestCase):
    def rule(self, **extra):
        return Config.from_dict(
            {"allow": [{"name": "r", "argv0": "^r$", **extra}]}, "test.toml"
        ).allow[0]

    def test_defaults_are_unconstrained(self):
        rule = self.rule()
        self.assertIsNone(rule.min_args)
        self.assertIsNone(rule.max_args)

    def test_zero_is_a_meaningful_maximum(self):
        self.assertEqual(self.rule(max_args=0).max_args, 0)

    def test_negative_is_rejected(self):
        with self.assertRaises(ConfigError) as caught:
            self.rule(min_args=-1)
        self.assertIn("min_args", str(caught.exception))

    def test_a_non_integer_is_rejected(self):
        with self.assertRaises(ConfigError):
            self.rule(max_args="2")

    def test_an_impossible_range_is_rejected(self):
        with self.assertRaises(ConfigError) as caught:
            self.rule(min_args=3, max_args=1)
        self.assertIn("never match", str(caught.exception))


class TestPatternListsMustBeLists(unittest.TestCase):
    """A bare string splits into characters, one of which is '$'.

    That matches everything, so a missing pair of brackets would silently turn
    a default-deny allowlist into match-anything.
    """

    RULE_FIELDS = ["args_allow", "args_deny", "cwd_allow"]

    def test_string_in_an_allow_rule_is_rejected(self):
        for field in self.RULE_FIELDS:
            with self.subTest(field=field):
                with self.assertRaises(ConfigError) as caught:
                    load(allow=[{**MINIMAL_ALLOW[0], field: "^-l$"}])
                self.assertIn(field, str(caught.exception))

    def test_string_in_allowed_refs_is_rejected(self):
        with self.assertRaises(ConfigError) as caught:
            load(sync={"allowed_refs": "^main$"})
        self.assertIn("allowed_refs", str(caught.exception))

    def test_non_string_element_is_rejected(self):
        with self.assertRaises(ConfigError):
            load(sync={"allowed_refs": ["^main$", 5]})

    def test_a_real_list_still_works(self):
        cfg = load(sync={"allowed_refs": ["^main$"]})
        self.assertEqual([p.pattern for p in cfg.sync.allowed_refs], ["^main$"])
        self.assertFalse(any(p.search("evil/../x") for p in cfg.sync.allowed_refs))


if __name__ == "__main__":
    unittest.main()

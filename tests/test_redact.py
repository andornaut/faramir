"""Tests for the redaction pipeline -- the piece everything else depends on."""

import base64
import json
import os
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from secretd.redact import (  # noqa: E402
    EligibilityPolicy,
    Redactor,
    shannon_entropy,
    strip_ansi,
    token_for,
    variants,
)

SECRET = "hunter2-correct-horse-battery"
REF = "home/router/admin"
TOKEN = token_for(REF)


def redact(text, secrets=((REF, SECRET),), **kw):
    return Redactor(list(secrets), **kw).redact_text(text)


class TestAnsiStripping(unittest.TestCase):
    def test_strips_colour_codes(self):
        self.assertEqual(strip_ansi("\x1b[31mred\x1b[0m"), "red")

    def test_strips_osc(self):
        self.assertEqual(strip_ansi("\x1b]0;title\x07text"), "text")

    def test_normalises_crlf(self):
        self.assertEqual(strip_ansi("a\r\nb"), "a\nb")

    def test_keeps_tabs_and_newlines(self):
        self.assertEqual(strip_ansi("a\tb\nc"), "a\tb\nc")

    def test_colour_spliced_into_secret_is_defeated(self):
        # The reason ANSI stripping happens *before* matching.
        mangled = SECRET[:5] + "\x1b[32m" + SECRET[5:]
        self.assertNotIn(SECRET, redact(mangled))
        self.assertIn(TOKEN, redact(mangled))


class TestValueSet(unittest.TestCase):
    def test_raw(self):
        self.assertIn(SECRET, variants(SECRET))

    def test_base64_padded_and_unpadded(self):
        vs = variants(SECRET)
        b64 = base64.b64encode(SECRET.encode()).decode()
        self.assertIn(b64, vs)
        self.assertIn(b64.rstrip("="), vs)

    def test_url_encoded(self):
        value = "p@ss w/rd+special"
        self.assertIn(urllib.parse.quote(value, safe=""), variants(value))
        self.assertIn(urllib.parse.quote_plus(value), variants(value))

    def test_json_escaped(self):
        value = 'quote"back\\slash'
        self.assertIn(json.dumps(value)[1:-1], variants(value))

    def test_shell_quoted_forms(self):
        value = "it's a $secret"
        vs = variants(value)
        self.assertIn("it'\\''s a $secret", vs)
        self.assertIn("it's a \\$secret", vs)


class TestMatching(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(redact(f"password is {SECRET}!"), f"password is {TOKEN}!")

    def test_base64(self):
        encoded = base64.b64encode(SECRET.encode()).decode()
        self.assertEqual(redact(f"blob {encoded} end"), f"blob {TOKEN} end")

    def test_base64_unpadded(self):
        encoded = base64.b64encode(SECRET.encode()).decode().rstrip("=")
        self.assertIn(TOKEN, redact(encoded))

    def test_base64_line_wrapped(self):
        # `base64` wraps at 76 columns by default; the value is split across
        # lines and would survive naive matching.
        long_secret = "A7f" + "x9Kq2mZp" * 12
        encoded = base64.encodebytes(long_secret.encode()).decode()
        self.assertIn("\n", encoded.strip())
        out = redact(encoded, secrets=[(REF, long_secret)])
        self.assertNotIn(encoded.strip().split("\n")[0], out)
        self.assertIn(TOKEN, out)

    def test_url_encoded_in_output(self):
        value = "p@ss w/rd"
        out = redact(f"GET /x?k={urllib.parse.quote(value, safe='')}", secrets=[(REF, value)])
        self.assertIn(TOKEN, out)

    def test_json_output(self):
        value = 'has"quote-and-more'
        out = redact(json.dumps({"pw": value}), secrets=[(REF, value)])
        self.assertNotIn(value, out)

    def test_multiple_occurrences_counted(self):
        r = Redactor([(REF, SECRET)])
        r.redact_text(f"{SECRET} {SECRET} {SECRET}")
        self.assertEqual(r.summary(), [{"token": TOKEN, "count": 3}])

    def test_longest_secret_wins(self):
        short, long = "abcdefgh12", "abcdefgh12345678"
        out = redact(long, secrets=[("short", short), ("long", long)])
        self.assertEqual(out, token_for("long"))

    def test_unrelated_output_survives(self):
        text = "TASK [common : install packages] ok: [router1]\n"
        self.assertEqual(redact(text), text)

    def test_token_is_stable(self):
        self.assertEqual(redact(SECRET), redact(SECRET))


class TestStreaming(unittest.TestCase):
    def test_split_across_chunks(self):
        r = Redactor([(REF, SECRET)])
        out = "".join(r.feed(SECRET[i : i + 3]) for i in range(0, len(SECRET), 3))
        out += r.flush()
        self.assertEqual(out, TOKEN)

    def test_split_one_byte_at_a_time(self):
        r = Redactor([(REF, SECRET)])
        out = "".join(r.feed(ch) for ch in f"pre {SECRET} post") + r.flush()
        self.assertEqual(out, f"pre {TOKEN} post")

    def test_escape_split_across_chunks(self):
        r = Redactor([(REF, SECRET)])
        out = r.feed("a\x1b[") + r.feed("31mb") + r.flush()
        self.assertEqual(out, "ab")

    def test_nothing_leaks_before_flush(self):
        r = Redactor([(REF, SECRET)])
        emitted = r.feed(f"header {SECRET[:-1]}")
        self.assertNotIn(SECRET[:10], emitted)

    def test_counts_not_double_counted_across_chunks(self):
        r = Redactor([(REF, SECRET)])
        for _ in range(4):
            r.feed(SECRET + " padding padding padding padding padding padding ")
        r.flush()
        self.assertEqual(r.counts[TOKEN], 4)


class TestEligibility(unittest.TestCase):
    def test_short_secret_is_skipped(self):
        r = Redactor([("short", "abc")])
        self.assertFalse(r.active)
        self.assertEqual(r.skipped[0][0], "short")

    def test_low_variety_is_skipped(self):
        r = Redactor([("boring", "aaaaaaaaaaaa")])
        self.assertFalse(r.active)

    def test_low_entropy_is_skipped(self):
        r = Redactor([("repeat", "abababababababab")])
        self.assertFalse(r.active)

    def test_skipping_leaves_output_untouched(self):
        # A 3-char secret would otherwise redact random substrings everywhere.
        text = "the cat sat on the mat"
        self.assertEqual(redact(text, secrets=[("s", "cat")]), text)

    def test_threshold_is_configurable(self):
        policy = EligibilityPolicy(min_length=3, min_unique_chars=2, min_entropy_bits_per_char=0.5)
        out = redact("the cat sat", secrets=[("s", "cat")], policy=policy)
        self.assertIn(token_for("s"), out)

    def test_entropy(self):
        self.assertAlmostEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)


class TestKnownLimits(unittest.TestCase):
    """The boundary of the threat model, asserted so nobody assumes otherwise."""

    def test_reversed_secret_is_not_caught(self):
        out = redact(SECRET[::-1])
        self.assertNotIn(TOKEN, out)  # documented in the README as expected

    def test_partial_secret_is_not_caught(self):
        out = redact(SECRET[:4])
        self.assertNotIn(TOKEN, out)


if __name__ == "__main__":
    unittest.main()

"""Streaming, encoding-aware redaction of secret values.

The redactor sits between the child process's PTY and the response that goes
back to the agent.  It has to work on a stream (output arrives in arbitrary
chunks) and it has to catch a value even when the program that printed it
mangled the bytes on the way out -- colour codes spliced into the middle,
base64 with line wrapping, URL escaping, shell quoting.

See ``docs/redaction.md`` for the reasoning behind each stage.
"""

from __future__ import annotations

import base64
import json
import math
import re
import shlex
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Sequence

# --------------------------------------------------------------------------
# Stage 1: ANSI / control-character stripping
# --------------------------------------------------------------------------

_ANSI_RE = re.compile(
    "|".join(
        [
            r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)",  # OSC ... BEL / ST
            r"\x1b[P^_X][^\x1b]*\x1b\\",  # DCS / PM / APC / SOS
            r"\x1b\[[0-?]*[ -/]*[@-~]",  # CSI
            r"\x1b[()][B0UK]",  # charset selection
            r"\x1b[@-Z\\-_]",  # two-character escapes
            r"[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]",  # stray controls
        ]
    )
)

# How far back an incomplete escape sequence may reasonably start.
_MAX_ESCAPE_LEN = 64


def strip_ansi(text: str) -> str:
    """Remove escape sequences and normalise CRLF.  Not stream-safe on its own."""
    return _ANSI_RE.sub("", text).replace("\r\n", "\n")


def _strip_ansi_stream(buf: str) -> tuple[str, str]:
    """Strip escapes from ``buf``, holding back a possibly-incomplete tail.

    Returns ``(clean, carry)``.  ``carry`` is text that must be prepended to the
    next chunk because it may be the beginning of an escape sequence (or a lone
    ``\\r`` that could turn out to be the first half of a CRLF).
    """
    carry_start = len(buf)
    esc = buf.rfind("\x1b")
    if esc != -1 and len(buf) - esc <= _MAX_ESCAPE_LEN:
        # Only hold back if the sequence is not obviously already terminated.
        if not _ANSI_RE.match(buf, esc):
            carry_start = esc
    if carry_start == len(buf) and buf.endswith("\r"):
        carry_start = len(buf) - 1
    head, carry = buf[:carry_start], buf[carry_start:]
    return strip_ansi(head), carry


# --------------------------------------------------------------------------
# Stage 2: the expanded value set
# --------------------------------------------------------------------------


def base64_variants(value: str) -> set[str]:
    """Base64 encodings of ``value``: standard and URL-safe, padded and not."""
    raw = value.encode("utf-8", "surrogatepass")
    out: set[str] = set()
    for enc in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
        text = enc.decode("ascii")
        out.add(text)
        out.add(text.rstrip("="))
    return out


def variants(value: str) -> set[str]:
    """Every rendering of ``value`` the redactor knows how to recognise.

    Deliberately *not* exhaustive -- an agent that wants to defeat this can
    (see the threat model).  These are the encodings that ordinary tools
    produce by accident: JSON output, URLs, ``set -x`` traces, base64 dumps.
    """
    out: set[str] = {value}
    out |= base64_variants(value)
    out.add(urllib.parse.quote(value, safe=""))
    out.add(urllib.parse.quote_plus(value))
    out.add(json.dumps(value)[1:-1])  # JSON string escaping, without the quotes
    out.add(shlex.quote(value))  # 'value' or value
    out.add(value.replace("'", "'\\''"))  # body of a shell single-quoted string
    out.add(
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("`", "\\`")
    )  # body of a shell double-quoted string
    return {v for v in out if v}


# --------------------------------------------------------------------------
# Stage 3: eligibility -- refuse to redact values that would eat the output
# --------------------------------------------------------------------------


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass(frozen=True)
class EligibilityPolicy:
    min_length: int = 8
    min_unique_chars: int = 4
    min_entropy_bits_per_char: float = 1.5

    def check(self, value: str) -> str | None:
        """Return ``None`` if the value may be redacted, else a reason string."""
        if len(value) < self.min_length:
            return f"shorter than {self.min_length} characters"
        if len(set(value)) < self.min_unique_chars:
            return f"fewer than {self.min_unique_chars} distinct characters"
        entropy = shannon_entropy(value)
        if entropy < self.min_entropy_bits_per_char:
            return f"low entropy ({entropy:.2f} bits/char)"
        return None


def token_for(ref: str) -> str:
    """The stable placeholder a secret is replaced with.

    Stable across turns and across processes so the model can reason about
    "the router password" without ever seeing it.
    """
    return f"«SECRET:{ref}»"


# --------------------------------------------------------------------------
# Stage 4: the streaming redactor
# --------------------------------------------------------------------------


@dataclass
class _Entry:
    ref: str
    token: str
    pattern: re.Pattern[str]
    wrapped: re.Pattern[str] | None
    longest: int


class Redactor:
    """Replaces every known secret rendering with a stable token.

    Usage::

        r = Redactor([("home/router/admin", "hunter2hunter2")])
        out = r.feed(chunk) + ... + r.flush()
        r.counts  # {token: occurrences}

    ``feed`` withholds a tail of the stream so a value split across two reads
    is still caught; ``flush`` releases it.
    """

    def __init__(
        self,
        secrets: Sequence[tuple[str, str]],
        policy: EligibilityPolicy | None = None,
    ) -> None:
        self.policy = policy or EligibilityPolicy()
        self.skipped: list[tuple[str, str]] = []
        self.counts: Counter[str] = Counter()
        self._entries: list[_Entry] = []
        self._ansi_carry = ""
        self._buf = ""

        seen: set[str] = set()
        for ref, value in secrets:
            if not isinstance(value, str) or value in seen:
                continue
            reason = self.policy.check(value)
            if reason is not None:
                self.skipped.append((ref, reason))
                continue
            seen.add(value)
            self._entries.append(self._compile(ref, value))

        # Longest value first: if one secret is a substring of another, the
        # longer token must win.
        self._entries.sort(key=lambda e: e.longest, reverse=True)
        longest = max((e.longest for e in self._entries), default=0)
        # x2 covers base64 line wrapping (newlines inserted inside a value),
        # +16 covers quoting expansion at a chunk boundary.
        self.overlap = longest * 2 + 16

    @staticmethod
    def _compile(ref: str, value: str) -> _Entry:
        vs = sorted(variants(value), key=len, reverse=True)
        pattern = re.compile("|".join(re.escape(v) for v in vs))
        b64 = sorted(base64_variants(value), key=len, reverse=True)
        wrapped = re.compile("|".join(re.escape(v) for v in b64)) if b64 else None
        return _Entry(ref, token_for(ref), pattern, wrapped, max(len(v) for v in vs))

    # -- public API --------------------------------------------------------

    @property
    def active(self) -> bool:
        return bool(self._entries)

    def feed(self, text: str) -> str:
        """Absorb a chunk of raw output; return the part that is safe to emit."""
        if not text:
            return ""
        self._ansi_carry += text
        clean, self._ansi_carry = _strip_ansi_stream(self._ansi_carry)
        self._buf = self._redact(self._buf + clean)
        if len(self._buf) > self.overlap:
            out, self._buf = self._buf[: -self.overlap], self._buf[-self.overlap :]
            return out
        return ""

    def flush(self) -> str:
        """Release everything held back.  Call once, at end of stream."""
        tail = strip_ansi(self._ansi_carry)
        self._ansi_carry = ""
        out = self._redact(self._buf + tail)
        self._buf = ""
        return out

    def redact_text(self, text: str) -> str:
        """One-shot convenience for text that is already complete."""
        return self.feed(text) + self.flush()

    def summary(self) -> list[dict[str, object]]:
        """``redactions`` field of the wire response: tokens and counts, no values."""
        return [
            {"token": token, "count": count}
            for token, count in sorted(self.counts.items())
            if count
        ]

    # -- internals ---------------------------------------------------------

    def _redact(self, text: str) -> str:
        if not text:
            return text
        for entry in self._entries:
            if entry.wrapped is not None and ("\n" in text or "\r" in text):
                text = self._sub_wrapped(text, entry)
            text, n = entry.pattern.subn(entry.token, text)
            if n:
                self.counts[entry.token] += n
        return text

    def _sub_wrapped(self, text: str, entry: _Entry) -> str:
        """Catch base64 that has been line-wrapped (``base64`` wraps at 76 cols).

        Matching happens on a copy of the haystack with newlines removed; hits
        are mapped back to spans in the original text so the surrounding output
        is preserved.
        """
        assert entry.wrapped is not None
        keep: list[str] = []
        index: list[int] = []
        for i, ch in enumerate(text):
            if ch not in "\n\r":
                keep.append(ch)
                index.append(i)
        if len(keep) == len(text):
            return text  # no newlines to collapse; the plain pass handles it
        view = "".join(keep)

        spans: list[tuple[int, int]] = []
        for m in entry.wrapped.finditer(view):
            start, end = index[m.start()], index[m.end() - 1] + 1
            if "\n" in text[start:end] or "\r" in text[start:end]:
                spans.append((start, end))
        if not spans:
            return text

        pieces: list[str] = []
        cursor = 0
        for start, end in spans:
            if start < cursor:  # overlapping match, already covered
                continue
            pieces.append(text[cursor:start])
            pieces.append(entry.token)
            self.counts[entry.token] += 1
            cursor = end
        pieces.append(text[cursor:])
        return "".join(pieces)

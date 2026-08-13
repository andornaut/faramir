# How the redactor works

[internal/redact](../internal/redact). Each stage exists for a case that is not obvious from the stage itself.

## The value set is everything the keeper manages

`op run`, `chamber exec` and `sops exec-env` mask the values *they* injected. A credential reaches the output by paths no injector knows about: a managed host printing its own configuration over `ssh` emits the password in the sops file whether or not that ref was injected, and a grep across a log file finds one written weeks ago.

So the broker holds every managed value, not the subset the current command names. It refetches on startup, when a file's fingerprint changes, and when the previous fetch could not reach the keeper: the files are unchanged in that case, so the poll would never notice, and an empty value set redacts nothing.

The fingerprints come from the keeper rather than a stat, the secrets being group-readable by the keeper alone, and `[secrets] patterns` globs are expanded there per request, so a file dropped into the secrets directory is picked up within `refresh_interval_sec` with no daemon to restart.

## Why a PTY and not a pipe

Programs behave differently when stdout is not a terminal: colour, progress meters and buffering all change. More to the point, **a process can write straight to `/dev/tty`**, which no stdout redirection sees and the controlling terminal does; `ssh` and `sudo` do it for password prompts. `internal/e2e` pins it: a secret written to `/dev/tty` comes back as a token.

The broker creates the pair, passes the *slave* over `SCM_RIGHTS` and keeps the master, so redaction runs with no extra hop. Stdin is `/dev/null`, or any command reading it blocks until timeout holding a concurrency slot. Cost: stdout and stderr arrive merged.

## The pipeline, in order

Each stage assumes the previous one has run.

**1. Strip ANSI escapes.** A colour code spliced into a value defeats matching while rendering identically (`hunte\x1b[32mr2-correct-horse`). The response carries the stripped text. An escape can split across two reads, so a bounded trailing partial sequence is held back.

This stage has a second reader. CSI, OSC and the C0 controls go here, which is why an approval prompt and `faramir logs` are not full of them; what it leaves is a bare `\r` (only CRLF is normalised), `ESC` followed by a byte outside `@-Z` and `\-_`, and the C1 controls `U+0080` to `U+009F`, which the patterns above do not reach: they match CSI as `ESC [`, and `U+009B` is the single-character form of the same introducer. [internal/termsafe](../internal/termsafe/termsafe.go) renders all three before any of them reaches a terminal. Narrowing what is stripped here widens what termsafe has to catch, and its tests name the cases so the pair stays legible.

**2. Match an expanded value set.** Not exhaustive by design: an agent that *wants* to defeat this can. These are what ordinary tools produce by accident.

Variant | Produced by
--- | ---
raw | anything
base64, padded and unpadded | `\| base64`, JSON payloads, `Authorization: Basic`
base64 URL-safe | JWTs, signed URLs
base32, padded and unpadded | TOTP seeds, `otpauth://` URIs, some token formats
hex, lower and upper case | `xxd -p`, `od -An -tx1`, `hexdump`, `openssl`, hex BLOB columns
percent-encoded, with `%20` and with `+` for a space | any URL or form body carrying a credential
JSON string-escaped, and with `\/` | `-vvv` output, API responses, PHP `json_encode`
shell single-quoted, both the `'\''` and `'"'"'` escapes | `set -x` traces, Python's `shlex.quote`
shell double-quoted (`\$`, `` \` ``, `\"`) | `set -x` traces

The set is still not exhaustive: `printf %q`'s backslash re-quoting, and any deliberate transform (`\| rev`, `\| tr a-z A-Z`, a hash), are outside it and always will be, because the child chooses its own output encoding.

HTML and XML entity escaping is outside it too, and deliberately so rather than for want of writing it down. Every encoding above has one spelling or a closed set of them, which is what makes enumerating it possible; entity escaping has a named, a decimal and a hexadecimal form per character, and the encoder chooses which characters to escape at all, so `&#112;` for a plain `p` is as valid as leaving it alone. A list of renderings would cover whichever producer it was written against and read as covering the rest. `set -x` itself is covered: bash quotes its xtrace with single quotes, which the raw and single-quoted variants already catch.

**3. A wrapped rendering needs a second pass.** `base64` wraps at 76 columns by default, and `fold` wraps the raw value and every other variant across lines the same way, so the rendering arrives with newlines inside it and matches nothing on a line-by-line view. The redactor matches the **whole** variant set against a newline-free view and maps hits back to spans in the original; a guard keeps this pass to matches that genuinely straddle a line break, so the plain pass still owns everything on one line.

Newlines are all that is removed. A continuation the formatter **indents** keeps its leading whitespace between the fragments and is not caught: `pr`, and the nested fields of `openssl -text`, wrap that way. `fmt` breaks at word boundaries and never splits a value at all. Collapsing the indentation as well would join any two words straddling an indented line break, which corrupts more output than the wrapping it would catch.

Cost: a low-entropy value split across a line break can be redacted where its two halves were unrelated words, the same fail-toward-redaction tradeoff the minimum-length gate makes, never a leak. The token replaces the **whole** span including the line break inside it, so such a match also joins the two lines: with `password` managed, `"the pass\nword list is here"` comes back as `"the «SECRET:ref» list is here"`.

**4. Stream with an overlap buffer.** A tail longer than the longest variant is held back on every `Feed` and released on `Flush`, the margin exceeding that variant because wrapping inserts newlines inside a value. The tail is already redacted, so re-scanning cannot double-count. Everything `Feed` returns is output, including the release triggered by the last partial-rune tail, or every command whose last write splits a rune loses its final characters.

The buffer only covers a join it is on both sides of, so **one redactor has to span the whole of a stream**. A brokered command gets that: the broker keeps one for the PTY it is reading. `faramir redact` gets it by sending every chunk of one input down one connection, which is what [`more`](protocol.md#streaming-a-redact) is for. A redactor per chunk would leave the break between two of them scanned by neither, and a client has to break a line longer than one chunk somewhere.

**5. Minimum length gate.** A short password redacts unrelated output at random: if `cat` is a secret, "concatenate" gets mangled. `[secrets] min_length` is the floor, and a value under it is **refused at load**: not held, not listed, not injectable.

Length is the whole of the test. There is no distinct-character count and no entropy floor: neither is the strength check it reads as (`password` clears both), and how strong a credential is belongs to whoever chose it. Length is different in kind, being a bound on what the redactor can search for without eating the output. A long low-entropy value such as `aaaaaaaa` matches any run of eight, but that mangles the operator's own output rather than letting a value escape.

Refusal closes the injection half only. A refused value is absent from the redactor, so reaching the output another way it arrives in plaintext, which is why the list stays operator-side: the broker logs each one at load and `faramir broker --check` reports them under `secrets.not_redactable` and exits non-zero, while `faramir status` and `faramir list-secrets` say nothing. Lengthen the secret rather than lowering the threshold.

**6. Stable tokens.** The same secret is always `«SECRET:home/router/admin»`, in every response and session. Two refs holding the same value share one token, the redactor deduplicating by value and keeping the first ref by name, so which of the two names it is does not move between restarts. Guillemets because they essentially never occur in tool output.

## What comes back is text, not bytes

Stage 1 is why, and it applies on both paths: `faramir run` and a `faramir redact` stream normalise identically.

Byte | What arrives
--- | ---
`\t`, `\n`, a bare `\r` | kept, CRLF normalised to `\n`
every other C0 control, and `\x7f` | dropped
a byte that is not valid UTF-8 | `U+FFFD`, which is three bytes
an ANSI escape sequence | removed, the text around it kept

So a command whose output is not text does not come back as it was written: 4096 random bytes arrive as roughly 7000, and an archive piped through will not open. That is the price of stage 1, and stage 1 is what catches a value spliced with colour codes.

Because a caller cannot see that from the output itself, `run` reports it the way it reports truncation, on stderr and suppressed by `--quiet`:

```
[faramir] 1735 non-text byte(s) replaced; log_id=...
```

Only a replaced byte is counted, never a stripped escape: colour is the ordinary case and says nothing about bytes being lost, while an invalid byte is the signal that the output was binary. Redirect stdout to a file and the file is unchanged by any of this; the notice is on the other stream.

## The age key is not in the value set

No process the broker starts receives the key, can read it (`0400 faramir-keeper`), or can open the keeper's socket, so "no child prints the age key" holds by construction rather than by the matcher catching it. Covering it here would be weaker than it looks: a child holding the key could write it to a file, and redaction only sees output.

## The audit log is redacted too

Output is recorded *after* redaction, so the tokens the agent saw are what reaches disk, and `argv` is redacted on the way in because a caller can put a value there even though the broker never does. An unredacted log would be the only plaintext this system writes to disk: beside encrypted sops files, unbounded, and in `/var/log` where backups and log shippers reach and the `0600` mode does not follow.

Cost: the log cannot say whether the value that arrived was current or stale. Compare the ref at the source. A value refused at load lands there in plaintext if it reaches output at all; `--check` names every such ref.

## Deliberately not done

- **No hashing or fuzzy matching.** The transformation space is unbounded; this is the documented boundary of the threat model.
- **No redaction of the request.** The agent chooses what it sends.
- **No reversal of a token.** Nothing maps `«SECRET:ref»` back to a value, including for the operator.

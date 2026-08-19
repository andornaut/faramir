# How the redactor works

[internal/redact](../internal/redact). Each stage exists for a case the stage itself does not make obvious.

## The value set is everything the keeper manages

`op run`, `chamber exec` and `sops exec-env` mask the values *they* injected. A credential reaches the output by paths no injector knows about: a managed host printing its own configuration over `ssh` emits the password in the sops file whether or not that ref was injected, and a grep across a log file finds one written weeks ago.

So the broker holds every managed value, not the subset the current command names. It refetches on startup, when a file's fingerprint changes, and when the previous fetch could not reach the keeper: the files are unchanged in that case, so the poll would never notice, and an empty value set redacts nothing.

The fingerprints come from the keeper rather than a stat, the secrets being group-readable by the keeper alone, and the managed store globs are expanded there per request, so a file dropped into the secrets directory is picked up within `min_refresh_sec` with no daemon to restart.

`[[secret.link]]` values are in the same set, on a different clock:

Source | When it is re-read
--- | ---
the managed store | At most once per [`min_refresh_sec`](configuration.md#what-a-flag-sets), checked when a command arrives rather than on a timer, so an idle host makes no round trip
a linked file | **Every** request. The file is the operator's own and this uid can stat it, so nothing is saved by waiting

The difference is deliberate. A linked file changes when another tool rotates the credential, which is not something the operator schedules, and a value missing from the redactor for up to a minute is a window nobody chose. Linking is mostly *for* this: the file is one the agent could read directly, and a value in the set is one a brokered command cannot print in the clear.

## Why a PTY and not a pipe

Programs behave differently when stdout is not a terminal: colour, progress meters and buffering all change. More to the point, **a process can write straight to `/dev/tty`**, which no stdout redirection sees; `ssh` and `sudo` do it for password prompts.

The child gets a PTY for stdout and stderr and no controlling terminal, so `/dev/tty` cannot be opened at all and a prompt falls back to stderr, which the redactor is reading. `internal/execserver` pins the failed open and that stderr is still captured; the end-to-end suites pin the same open failing on a real host (`check-ssh.sh`) and stderr coming back as a token (`check-wrap.sh`).

The broker creates the pair, passes the *slave* over `SCM_RIGHTS` and keeps the master, so redaction runs with no extra hop. Stdin is `/dev/null`, or any command reading it blocks until timeout holding a concurrency slot. Cost: stdout and stderr arrive merged.

## The pipeline, in order

Each stage assumes the previous one has run.

**1. Strip ANSI escapes.** A colour code spliced into a value defeats matching while rendering identically (`hunte\x1b[32mr2-correct-horse`). The response carries the stripped text. An escape can split across two reads, so a bounded trailing partial sequence is held back.

Escapes only. A zero-width separator spliced between the characters (`U+200B`, `U+200D`, `U+2060`, `U+00AD`) renders identically too and is not removed, so a value written that way is not matched. Stripping them would be stripping ordinary text, which soft hyphens and joiners are in the languages that use them; and it needs deliberate crafting, the same class as `| rev`.

This stage has a second reader. CSI, OSC and the C0 controls go here, which is why an escalation prompt and `faramir logs` are not full of them. What it leaves is a bare `\r` (only CRLF is normalised), `ESC` followed by a byte outside `@-Z` and `\-_`, and the C1 controls `U+0080` to `U+009F`, the patterns matching CSI as `ESC [` while `U+009B` is the single-character form of the same introducer. [internal/termsafe](../internal/termsafe/termsafe.go) renders all three before any reaches a terminal, so narrowing what is stripped here widens what termsafe has to catch.

**2. Match an expanded value set.** Not exhaustive by design: an agent that *wants* to defeat this can. These are what ordinary tools produce by accident.

Variant | Produced by
--- | ---
raw | anything
base64, padded and unpadded | `\| base64`, JSON payloads, `Authorization: Basic`
base64 URL-safe, padded and unpadded | JWTs, signed URLs
base32, padded and unpadded | TOTP seeds, `otpauth://` URIs, some token formats
hex, lower and upper case | `xxd -p`, `od -An -tx1`, `hexdump`, `openssl`, hex BLOB columns
percent-encoded, with `%20` and with `+` for a space | any URL or form body carrying a credential
JSON string-escaped, and with `\/` | `-vvv` output, API responses, PHP `json_encode`
shell single-quoted, both the `'\''` and `'"'"'` escapes | `set -x` traces, Python's `shlex.quote`
shell double-quoted (`\\`, `\$`, `` \` ``, `\"`) | `set -x` traces

Outside it and always will be: `printf %q`'s backslash re-quoting, and any deliberate transform (`\| rev`, `\| tr a-z A-Z`, a hash), because the child chooses its own output encoding.

HTML and XML entity escaping is outside it deliberately. Every encoding above has one spelling or a closed set of them, which is what makes enumerating it possible. Entity escaping has a named, a decimal and a hexadecimal form per character, and the encoder chooses which characters to escape at all, so `&#112;` for a plain `p` is as valid as leaving it alone: a list of renderings would cover whichever producer it was written against and read as covering the rest.

**3. A wrapped rendering needs a second pass.** `base64` wraps at 76 columns, and `fold` wraps the raw value and every other variant the same way, so the rendering arrives with newlines inside it and matches nothing line by line. The redactor matches the whole variant set against a view with the line breaks removed and maps hits back to spans in the original; a guard keeps this pass to matches that genuinely straddle a break.

Line breaks are all that is removed, `\n` and a bare `\r`. A continuation the formatter **indents** keeps its leading whitespace between the fragments and is not caught: `pr`, and the nested fields of `openssl -text`, wrap that way. Collapsing indentation as well would join any two words straddling an indented break, corrupting more output than the wrapping it would catch.

Cost: a low-entropy value split across a line break can be redacted where its two halves were unrelated words. That fails toward redaction rather than toward a leak, as the length gate does. The token replaces the whole span including the break, so such a match also joins the two lines: with `password` managed, `"the pass\nword list is here"` comes back as `"the «SECRET:ref» list is here"`.

**4. Stream with an overlap buffer.** A tail of twice the longest variant plus a margin is held back on every `Feed` and released on `Flush`, the margin exceeding that variant because wrapping inserts newlines inside a value. The tail is already redacted, so re-scanning cannot double-count. Everything `Feed` returns is output, including the release triggered by the last partial-rune tail, or every command whose last write splits a rune loses its final characters.

The buffer only covers a join it is on both sides of, so **one redactor has to span the whole of a stream**. The broker keeps one for the PTY it is reading; `faramir redact` gets it by sending every chunk of one input down one connection, which is what [`more`](protocol.md#redact-and-streaming-it) is for.

A streaming `faramir redact` sends a chunk when it has a chunk's worth or after a short idle: without the idle, a backgrounded command that prints a line and then waits would hold that line until it produced a whole chunk or exited, which for a dev server is never. The idle chunk is still marked `more`, so the broker keeps holding the tail; only the last chunk releases it. The cost is that output shorter than the tail is not shown until more arrives or the input ends, the tail being exactly the bytes a value could still be split across.

**5. Minimum length gate.** A short password redacts unrelated output at random: if `cat` is a secret, "concatenate" gets mangled. [`[secret] min_length`](configuration.md#what-a-flag-sets) is the floor, and a value under it is **refused at load**: not held, not listed, not injectable.

Length is the whole of the test. There is no distinct-character count and no entropy floor: neither is the strength check it reads as (`password` clears both), and how strong a credential is belongs to whoever chose it. Length is a bound on what the redactor can search for without eating the output. A long low-entropy value such as `aaaaaaaa` matches any run of eight, but that mangles the operator's own output rather than letting a value escape.

Refusal closes the injection half only. A refused value is absent from the redactor, so reaching the output another way it arrives in plaintext, which is why the list stays operator-side: the broker logs each one at load and `faramir broker --check` reports them under `secrets.not_redactable` and exits non-zero, while `faramir status` and `faramir refs` say nothing. Lengthen the secret rather than lowering the threshold.

**6. Stable tokens.** The same secret is always `«SECRET:home/router/admin»`, in every response and session. Two refs holding the same value share one token, the redactor deduplicating by value and keeping the first ref by name, so which name it is does not move between restarts. Guillemets because they essentially never occur in tool output.

## What comes back is text, not bytes

Stage 1 is why, and it applies on both paths: `faramir run` and a `faramir redact` stream normalise identically.

Byte | What arrives
--- | ---
`\t`, `\n`, a bare `\r` | kept, CRLF normalised to `\n`
every other C0 control except `ESC`, and `\x7f` | dropped
an `ESC` beginning no recognised sequence | kept, and rendered by termsafe before it reaches a terminal
a byte that is not valid UTF-8 | `U+FFFD`, which is three bytes
an ANSI escape sequence | removed, the text around it kept

So a command whose output is not text does not come back as it was written: random bytes expand, and an archive piped through will not open. That is the price of stage 1, and stage 1 is what catches a value spliced with colour codes.

Because a caller cannot see that from the output itself, `run` reports it the way it reports truncation, on stderr and suppressed by `--quiet`:

```text
faramir run: 1735 non-text byte(s) replaced; log_id=...
```

Only a replaced byte is counted, never a stripped escape: colour is the ordinary case and says nothing about bytes being lost, while an invalid byte is the signal the output was binary. Redirect stdout to a file and the file is unchanged; the notice is on the other stream.

## The age key is not in the value set

No process the broker starts receives the key, can read it (`0400 faramir-keeper`), or can open the keeper's socket, so "no child prints the age key" holds by construction rather than by the matcher catching it. Covering it here would be weaker than it looks: a child holding the key could write it to a file, and redaction only sees output.

## The audit log is redacted too

Output is recorded *after* redaction, so the tokens the agent saw are what reaches disk, and `argv` is redacted on the way in because a caller can put a value there even though the broker never does. An unredacted log would be the only plaintext this system writes to disk: unbounded, and in `/var/log` where backups and log shippers reach and the `0600` mode does not follow.

Cost: the log cannot say whether the value that arrived was current or stale. Compare the ref at the source. A value refused at load lands there in plaintext if it reaches output at all; `--check` names every such ref.

## Deliberately not done

- **No hashing or fuzzy matching.** The transformation space is unbounded; this is the documented boundary of the threat model.
- **No redaction of the request.** The agent chooses what it sends.
- **No reversal of a token.** Nothing maps `«SECRET:ref»` back to a value, including for the operator.

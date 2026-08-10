# How the redactor works

[internal/redact](../internal/redact). Each stage exists for a case that is not obvious from the stage itself.

## The value set is everything the keeper manages

`op run`, `chamber exec` and `sops exec-env` mask the values *they* injected. A credential reaches the output by paths no injector knows about: a managed host printing its own configuration over `ssh` emits the password in the sops file whether or not that ref was injected, and a grep across a log file finds one written weeks ago.

So the broker holds every managed value, not the subset the current command names. It refetches on startup, when a file's fingerprint changes, and when the previous fetch could not reach the keeper: the files are unchanged in that case, so the poll would never notice, and an empty value set redacts nothing.

The fingerprints come from the keeper rather than a stat, the secrets being group-readable by the keeper alone, and `[secrets] files` globs are expanded there per request, so a file dropped into the secrets directory is picked up within `refresh_interval_sec` with no daemon to restart.

## Why a PTY and not a pipe

Programs behave differently when stdout is not a terminal: colour, progress meters and buffering all change. More to the point, **a process can write straight to `/dev/tty`**, which no stdout redirection sees and the controlling terminal does; `ssh` and `sudo` do it for password prompts. `internal/e2e` pins it: a secret written to `/dev/tty` comes back as a token.

The broker creates the pair, passes the *slave* over `SCM_RIGHTS` and keeps the master, so redaction runs with no extra hop. Stdin is `/dev/null`, or any command reading it blocks until timeout holding a concurrency slot. Cost: stdout and stderr arrive merged.

## The pipeline, in order

Each stage assumes the previous one has run.

**1. Strip ANSI escapes.** A colour code spliced into a value defeats matching while rendering identically (`hunte\x1b[32mr2-correct-horse`). The response carries the stripped text. An escape can split across two reads, so a bounded trailing partial sequence is held back.

**2. Match an expanded value set.** Not exhaustive by design: an agent that *wants* to defeat this can. These are what ordinary tools produce by accident.

Variant | Produced by
--- | ---
raw | anything
base64, padded and unpadded | `\| base64`, JSON payloads, `Authorization: Basic`
base64 URL-safe | JWTs, signed URLs
base32, padded and unpadded | TOTP seeds, `otpauth://` URIs, some token formats
hex, lower and upper case | `xxd -p`, `od -An -tx1`, `hexdump`, `openssl`, hex BLOB columns
percent-encoded | any URL carrying a credential
JSON string-escaped, and with `\/` | `-vvv` output, API responses, PHP `json_encode`
HTML/XML entity-escaped | a token reflected into an HTML page, fetched with `curl`
shell single-quoted (`'\''`) | `set -x` traces
shell double-quoted (`\$`, `` \` ``, `\"`) | `set -x` traces

The set is still not exhaustive: `printf %q`'s backslash re-quoting, and any deliberate transform (`\| rev`, `\| tr a-z A-Z`, a hash), are outside it and always will be, because the child chooses its own output encoding. `set -x` itself is covered -- bash quotes its xtrace with single quotes, which the raw and single-quoted variants already catch.

**3. A wrapped rendering needs a second pass.** `base64` wraps at 76 columns by default, and `fold`, `fmt`, `openssl x509 -text` and any width-aware pretty-printer wrap the raw value and every other variant across lines too, so the rendering arrives with newlines inside it and matches nothing on a line-by-line view. The redactor matches the **whole** variant set against a newline-free view and maps hits back to spans in the original; a guard keeps this pass to matches that genuinely straddle a line break, so the plain pass still owns everything on one line. Cost: a low-entropy value split across a line break can be redacted where its two halves were unrelated words -- the same fail-toward-redaction tradeoff the minimum-length gate makes, never a leak.

**4. Stream with an overlap buffer.** A tail longer than the longest variant is held back on every `Feed` and released on `Flush`, the margin exceeding that variant because wrapping inserts newlines inside a value. The tail is already redacted, so re-scanning cannot double-count. Everything `Feed` returns is output, including the release triggered by the last partial-rune tail, or every command whose last write splits a rune loses its final characters.

**5. Minimum length gate.** A short password redacts unrelated output at random: if `cat` is a secret, "concatenate" gets mangled. `[secrets] min_length` is the floor, and a value under it is **refused at load**: not held, not listed, not injectable.

Length is the whole of the test. There is no distinct-character count and no entropy floor: neither is the strength check it reads as (`password` clears both), and how strong a credential is belongs to whoever chose it. Length is different in kind, being a bound on what the redactor can search for without eating the output. A long low-entropy value such as `aaaaaaaa` matches any run of eight, but that mangles the operator's own output rather than letting a value escape.

Refusal closes the injection half only. A refused value is absent from the redactor, so reaching the output another way it arrives in plaintext, which is why the list stays operator-side: the broker logs each one at load and `faramir broker --check` reports them under `secrets.not_redactable` and exits non-zero, while `faramir_status` and `faramir_list_secrets` say nothing. Lengthen the secret rather than lowering the threshold.

**6. Stable tokens.** The same secret is always `«SECRET:home/router/admin»`, in every response and session. Two refs holding the same value share a token, the redactor deduplicating by value. Guillemets because they essentially never occur in tool output.

## The age key is not in the value set

No process the broker starts receives the key, can read it (`0400 faramir-keeper`), or can open the keeper's socket, so "no child prints the age key" holds by construction rather than by the matcher catching it. Covering it here would be weaker than it looks: a child holding the key could write it to a file, and redaction only sees output.

## The audit log is redacted too

Output is recorded *after* redaction, so the tokens the agent saw are what reaches disk, and `argv` is redacted on the way in because a caller can put a value there even though the broker never does. An unredacted log would be the only plaintext this system writes to disk: beside encrypted sops files, unbounded, and in `/var/log` where backups and log shippers reach and the `0600` mode does not follow.

Cost: the log cannot say whether the value that arrived was current or stale. Compare the ref at the source. A value refused at load lands there in plaintext if it reaches output at all; `--check` names every such ref.

## Deliberately not done

- **No hashing or fuzzy matching.** The transformation space is unbounded; this is the documented boundary of the threat model.
- **No redaction of the request.** The agent chooses what it sends.
- **No reversal of a token.** Nothing maps `«SECRET:ref»` back to a value, including for the operator.

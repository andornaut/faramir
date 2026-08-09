# How the redactor works

[internal/redact](../internal/redact). Each stage exists for a case that is not obvious from the stage itself.

## The value set is everything the keeper manages

`op run`, `chamber exec` and `sops exec-env` mask the values *they* injected. A credential reaches the output by paths no injector knows about: a managed host printing its own configuration over `ssh` emits the password in the sops file whether or not that ref was injected, and a grep across a log file finds one written weeks ago.

So the broker holds every managed value, not the subset the current command names. It refetches on startup, when a file's fingerprint changes, and when the previous fetch could not reach the keeper: the files are unchanged in that case, so the poll would never notice, and an empty value set redacts nothing.

The fingerprints come from the keeper rather than a stat, the store being group-readable by the keeper alone, and `[secrets] files` globs are expanded there per request, so a file dropped into the store is picked up within `refresh_interval_sec` with no daemon to restart.

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
percent-encoded | any URL carrying a credential
JSON string-escaped | `-vvv` output, API responses, structured logging
shell single-quoted (`'\''`) | `set -x` traces
shell double-quoted (`\$`, `` \` ``, `\"`) | `set -x` traces

**3. Wrapped base64 needs a second pass.** `base64` wraps by default, so the encoded value arrives with newlines inside it and matches nothing. The redactor matches against a newline-free view and maps hits back to spans in the original.

**4. Stream with an overlap buffer.** A tail longer than the longest variant is held back on every `Feed` and released on `Flush`, the margin exceeding that variant because base64 wrapping inserts newlines inside a value. The tail is already redacted, so re-scanning cannot double-count. Everything `Feed` returns is output, including the release triggered by the last partial-rune tail, or every command whose last write splits a rune loses its final characters.

**5. Minimum length and entropy gate.** A short password redacts unrelated output at random: if `cat` is a secret, "concatenate" gets mangled. `[secrets]` sets a minimum length, distinct-character count and entropy per character, and a value that fails is **refused at load**: not held, not listed, not injectable.

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

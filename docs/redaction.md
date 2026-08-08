# How the redactor works

[internal/redact](../internal/redact). Each stage exists for a case that is not obvious from the stage itself.

## Why not an off-the-shelf injector

`op run`, `chamber exec`, `sops exec-env` and friends mask the values *they* injected. A credential reaches the output by paths no injector knows about: a managed host printing its own configuration over `ssh` emits the very password in the sops file whether or not that ref was injected, and a grep across a log file finds one written weeks ago.

So **the value set is every secret the keeper manages**, not the subset relevant to the current command. The broker fetches it on startup, when a managed file's mtime changes, and again when the previous fetch could not reach the keeper (the files are unchanged in that case, so the mtime poll would never notice, and an empty value set redacts nothing).

Which files it watches is fixed at startup. `config.toml` is read once per daemon, so a file added to `[secrets] files` is adopted by restarting the keeper and then the broker.

## Why a PTY and not a pipe

1. Programs behave differently when stdout is not a terminal: colour, progress meters and buffering all change.
2. **A process can write straight to `/dev/tty`**, bypassing stdout redirection entirely. `ssh` and `sudo` do this for password prompts. A pipe never sees those writes; owning the controlling terminal does.

`internal/e2e` pins this: a secret written to `/dev/tty` comes back as a token.

The broker creates the pair, passes the *slave* over `SCM_RIGHTS` and keeps the master, so redaction runs where it always did with no extra hop.

Stdin is `/dev/null`. A readable stdin would mean any command that reads it blocks until timeout while holding a concurrency slot. Cost: stdout and stderr arrive merged, with no way to tell them apart. Accepted.

## The pipeline, in order

Each stage assumes the previous one has run.

### 1. Strip ANSI escapes

A colour code spliced into a value defeats naive matching while rendering identically:

```
hunte\x1b[32mr2-correct-horse
```

Escapes and stray control characters are removed first, and the response carries the stripped text. An escape can split across two reads, so the stripper holds back a bounded trailing partial sequence.

### 2. Match an expanded value set

Variant | Produced by
--- | ---
raw | anything
base64, padded and unpadded | `\| base64`, JSON payloads, `Authorization: Basic`
base64 URL-safe | JWTs, signed URLs
percent-encoded | any URL carrying a credential
JSON string-escaped | `-vvv` output, API responses, structured logging
shell single-quoted (`'\''`) | `set -x` traces
shell double-quoted (`\$`, `` \` ``, `\"`) | `set -x` traces

Deliberately not exhaustive: an agent that *wants* to defeat this can. These are the encodings ordinary tools produce by accident.

### 3. Wrapped base64 needs a second pass

`base64` wraps by default, so the encoded value arrives with newlines inside it and matches nothing. The redactor builds a newline-free view with an index map back to the original offsets, matches against that, and maps hits back to spans in the original.

### 4. Stream with an overlap buffer

A tail derived from the longest variant is held back on every `Feed` and released on `Flush`. The margin exceeds the longest variant because base64 wrapping inserts newlines inside a value. The retained tail is already redacted, so re-scanning cannot double-count: a token contains no secret.

Everything `Feed` returns is output, including the release triggered by the last partial-rune tail. Dropping that return would lose the final characters of every command whose last write splits a rune.

### 5. Minimum length and entropy gate

A short password redacts unrelated output at random: if `cat` is a secret, "concatenate" gets mangled.

`[secrets]` sets a minimum length, distinct-character count and Shannon entropy per character. A value that fails is **refused at load**: not held, not listed, not injectable.

Refusal does not make the value safe. A refused value is absent from the redactor, so if it reaches the output another way it arrives in plaintext. Refusal only closes the injection half.

The refused list stays operator-side, because it names exactly the secrets that are never tokenized:

- the broker logs a warning naming each one at load,
- `faramir-broker --check` reports them under `secrets.not_redactable` and exits non-zero,
- `faramir_status` and `faramir_list_secrets` say nothing about them.

Lengthen the secret rather than lowering the threshold.

### 6. Stable tokens

The same secret always becomes `«SECRET:home/router/admin»`, in every response and session. Two refs holding the same value share one token, since the redactor deduplicates by value. Guillemets because they essentially never occur in tool output.

## The age key is not in the value set

No process the broker starts receives the key, can read `/etc/faramir/age.key` (`0400 faramir-keeper`), or can open the keeper's socket. "No child prints the age key" holds by construction rather than by the matcher catching it on the way out.

Covering it in the redactor would be weaker than it looks: a child holding the key could write it to a file, and redaction only sees output.

## The audit log is redacted too

Output is recorded *after* redaction, so the tokens the agent saw are what reaches disk. Refs are names, and `argv` is redacted on the way in because a caller can put a value there even though the broker never does.

An unredacted log would be the only plaintext this system writes to disk: unencrypted beside encrypted sops files, unbounded, and in `/var/log` where backups and log shippers reach and the `0600` mode does not follow.

Cost: you cannot tell from the log whether the value that arrived was current or stale. Compare the ref at the source. A value refused at load is absent from the redactor, so if it reaches output another way it lands in the log in plaintext; `--check` names every such ref.

## Deliberately not done

- **No hashing or fuzzy matching.** The transformation space is unbounded. This is the documented boundary of the threat model, not an oversight.
- **No redaction of the request.** The agent chooses what it sends.
- **No reversal of a token.** There is no lookup from `«SECRET:ref»` back to a value anywhere, including for the operator.

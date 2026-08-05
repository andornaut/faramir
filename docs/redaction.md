# How the redactor works

The redactor is the only substantial piece of new code in this project
(`src/secretd/redact.py`, ~250 lines). Everything else is plumbing around uid
separation. This document explains why each stage exists, because several of
them look like over-engineering until you hit the case they exist for.

## Why not an off-the-shelf injector

`op run`, `chamber exec`, `sops exec-env` and friends mask the values *they*
injected into the child's environment. That is not sufficient here.

`ansible-playbook` decrypts vars itself, at run time, from a file the broker
never passed it. A vault var printed by a `debug:` task, or by `-vvv` output,
was never injected by anything — so an injector-based redactor has never seen
the value and cannot mask it.

Therefore: **the redactor's value set is every secret the broker manages**, not
the subset relevant to the current command. It is rebuilt on startup, on
`SIGHUP`, and when a managed file's mtime changes.

## Why a PTY and not a pipe

Two reasons, and the second is the one that matters.

1. Programs behave differently when stdout is not a terminal — colour
   disappears, progress meters change, buffering changes. Ansible's output in
   particular is much less useful through a pipe.
2. **A process can write straight to `/dev/tty`**, bypassing stdout redirection
   entirely. `ssh` and `sudo` do exactly this for password prompts. A pipe on
   stdout/stderr never sees those writes. Owning the controlling terminal does.

The `test_writes_to_dev_tty_are_captured_and_redacted` case in `tests/test_e2e.py`
pins this down: `printenv ROUTER_PW > /dev/tty` is captured and redacted.

The cost is that stdout and stderr arrive merged, with no way to tell them
apart. That is accepted.

## The pipeline, in order

Order matters; each stage assumes the previous one has run.

### 1. Strip ANSI escapes before matching

A colour code spliced into the middle of a value defeats naive matching:

```
hunte\x1b[32mr2-correct-horse
```

is not `hunter2-correct-horse` to any string matcher, but it renders
identically on a terminal — and would render identically in a transcript sent
to a model. So escapes and stray control characters are removed *first*, and
the response contains the stripped text.

Streaming complicates this: an escape sequence can be split across two reads.
The stripper holds back a trailing partial sequence (up to 64 bytes) and
prepends it to the next chunk.

### 2. Match an expanded value set

For every secret, these renderings are generated and matched:

| Variant | Produced by |
|---|---|
| raw | anything |
| base64, padded and unpadded | `\| base64`, `\| base64 -w0`, JSON payloads, `Authorization: Basic` |
| base64 URL-safe | JWTs, signed URLs |
| percent-encoded (`quote` and `quote_plus`) | any URL containing a credential |
| JSON string-escaped | `-vvv` output, API responses, structured logging |
| shell single-quoted body (`'\''`) | `set -x` traces |
| shell double-quoted body (`\$`, `` \` ``, `\"`) | `set -x` traces |

Not exhaustive, and deliberately so — an agent that *wants* to defeat this can
(see the threat model). These are the encodings ordinary tools produce by
accident.

### 3. Wrapped base64 needs a second pass

`base64` wraps at 76 columns by default, so the encoded value arrives with
newlines inside it and matches nothing. The redactor builds a copy of the
buffer with newlines removed, keeping an index map back to the original
offsets, matches the base64 variants against that view, and maps the hits back
to spans in the original text so surrounding output is preserved.

### 4. Stream with an overlap buffer

The redactor holds back `2 × max(len(variant)) + 16` characters of the tail on
every `feed()`, releasing them only on `flush()`. The doubling covers base64
line wrapping (newlines inserted *inside* a value make its on-the-wire length
longer than the variant itself).

Because the retained tail has already been redacted, re-scanning it on the next
chunk cannot double-count: a token contains no secret.

### 5. Minimum length and entropy gate

A short password redacts unrelated output at random. If `cat` is a secret, the
word "concatenate" gets mangled and the agent is left debugging a phantom.

Defaults: at least 8 characters, at least 4 distinct characters, at least 1.5
bits/char of Shannon entropy. Values that fail are **not redacted at all**, and:

- the broker logs a warning naming each one at load time,
- `list_secret_refs` marks them `NOT REDACTABLE: <reason>`,
- `broker_status` lists them under `not_redactable`.

The right fix is to lengthen the secret, not to lower the threshold — but the
thresholds are configurable in `[secrets]` if you have a genuinely short value
you would rather redact aggressively.

### 6. Stable tokens

The same secret always becomes `«SECRET:home/router/admin»`, in every response
and every session. Two refs holding the *same value* share one token — the
redactor deduplicates by value, so a password stored both as
`home/router/admin` and as `vault_router_password` renders as a single,
consistent name rather than alternating unpredictably. The model can then reason about "the router password"
across turns without ever holding it. Guillemets are used because they
essentially never occur in tool output, so a token is unambiguous.

## The age key is in the value set

Ansible has to decrypt sops vars itself, so `ansible` and `ansible-playbook`
receive `SOPS_AGE_KEY` (via `provide_age_key = true` on their allowlist rules).
Anything that can decrypt can also print the key it decrypted with, and that
would be a worse leak than any single credential — so the key material is
itself part of the redaction value set, under the ref `broker/age-key`.

Rules without `provide_age_key` — notably `bash` — never see it.

## What is deliberately not done

- **No hashing/fuzzy matching.** Redacting `sha256(secret)` would be easy and
  would not help: the transformation space is unbounded, and this is the
  documented boundary of the threat model, not an oversight.
- **No redaction of the request.** The agent chooses what it sends; the broker
  has nothing to hide from it there.
- **No attempt to redact the raw log.** That file exists precisely so the
  operator has the unredacted truth. It is 0600 `secretd`, and the agent is
  given a `log_id` to quote instead.

# How the redactor works

The redactor is the only substantial piece of new code in this project
([internal/redact](../internal/redact)). Everything else is plumbing around uid
separation. This document explains why each stage exists, because several of
them look like over-engineering until you hit the case they exist for.

## Why not an off-the-shelf injector

`op run`, `chamber exec`, `sops exec-env` and friends mask the values *they*
injected into the child's environment. That is not sufficient here.

A credential reaches the output by paths no injector knows about. A managed
host printing its own configuration over `ssh` emits the very password stored
in the sops file, whether or not that ref was injected into the command. A
grep across a log file finds one that was written there weeks ago. An
injector-based redactor has never seen those values and cannot mask them.

Therefore: **the redactor's value set is every secret the keeper manages**, not
the subset relevant to the current command. The broker fetches it on startup,
on `SIGHUP`, when a managed file's mtime changes, and again when the previous
fetch could not reach the keeper: the files are unchanged in that case, so the
mtime poll would never notice, and an empty value set redacts nothing.

## Why a PTY and not a pipe

Two reasons, and the second is the one that matters.

1. Programs behave differently when stdout is not a terminal: colour
   disappears, progress meters change, buffering changes. Ansible's output in
   particular is much less useful through a pipe.
2. **A process can write straight to `/dev/tty`**, bypassing stdout redirection
   entirely. `ssh` and `sudo` do exactly this for password prompts. A pipe on
   stdout/stderr never sees those writes. Owning the controlling terminal does.

`TestWritesToDevTtyAreCapturedAndRedacted` in `internal/e2e` pins this down:
`printenv ROUTER_PW > /dev/tty` is captured and comes back as a token.

The fork happens in `faramir-exec`, but the PTY does not move with it. The
broker creates the pair, passes the *slave* over `SCM_RIGHTS` and keeps the
master, so everything below runs exactly where it always did, on the child's
bytes, with no extra hop for output to take.

Output only: the child's stdin is `/dev/null`. Nothing ever writes to the
master, so a readable stdin would mean any command that reads it, a password
prompt or a shell started with no arguments, blocks until its timeout while
holding a concurrency slot. The controlling terminal is claimed through
stdout instead, which is what `/dev/tty` writes depend on.

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
identically on a terminal, and would render identically in a transcript sent
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

Not exhaustive, and deliberately so: an agent that *wants* to defeat this can
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
every `Feed`, releasing them only on `Flush`. The doubling covers base64 line
wrapping (newlines inserted *inside* a value make its on-the-wire length longer
than the variant itself).

Because the retained tail has already been redacted, re-scanning it on the next
chunk cannot double-count: a token contains no secret.

Everything `Feed` returns is output, including the release triggered by the
last partial-rune tail at end of stream. Dropping that return would lose the
final characters of every command whose last write splits a rune;
`TestOutputEndingMidRuneIsNotTruncated` in `internal/e2e` holds that down.

### 5. Minimum length and entropy gate

A short password redacts unrelated output at random. If `cat` is a secret, the
word "concatenate" gets mangled and the agent is left debugging a phantom.

Defaults: at least 8 characters, at least 4 distinct characters, at least 1.5
bits/char of Shannon entropy. A value that fails the gate is **refused at
load**: it is not held, not listed by `faramir_list_secrets`, and not
injectable. Asking for it returns an error naming the reason.

Refusing rather than serving-and-warning means the broker is never the thing
that hands over a value it cannot cover. It does not make the value safe. A
refused value is absent from the redactor, so if it reaches the output by
another route, a managed host printing its own configuration, it arrives in
plaintext. That is the same leak as before; refusal only closes the injection
half of it.

Which is why the refused list stays operator-side. It names exactly the
secrets that are never tokenized, which is a repair list for whoever can
lengthen them and targeting information for anyone else:

- the broker logs a warning naming each one at load time,
- `faramir-broker --check` reports them under `secrets.not_redactable`, with
  the reason, and exits non-zero,
- `faramir_status` and `faramir_list_secrets` say nothing about them.

The right fix is to lengthen the secret, not to lower the threshold, but the
thresholds are configurable in `[secrets]` if you have a genuinely short value
you would rather redact aggressively.

### 6. Stable tokens

The same secret always becomes `«SECRET:home/router/admin»`, in every response
and every session. Two refs holding the *same value* share one token: the
redactor deduplicates by value, so a password stored both as
`home/router/admin` and as `vault_router_password` renders as a single,
consistent name rather than alternating unpredictably. The model can then reason about "the router password"
across turns without ever holding it. Guillemets are used because they
essentially never occur in tool output, so a token is unambiguous.

## The age key is not in the value set

It used to be. When Ansible decrypted sops vars itself it received
`SOPS_AGE_KEY`, and anything that can decrypt can also print the key it
decrypted with, so the key material was added to the value set under the ref
`broker/age-key` and a child that printed it got a token.

That is gone, and its absence is the stronger arrangement. No process the
broker starts receives the key, can read `/etc/faramir/age.key` (owned by
`faramir-keeper`, mode 0400), or can open the keeper's socket. The property
"no child prints the age key" no longer rests on the matcher catching it on
the way out. Redaction is best-effort; a uid boundary is not.

Relying on the redactor here was always weaker than it looked: a child holding
the key could write it to a file or send it somewhere, and redaction only ever
sees output.

## What is deliberately not done

- **No hashing/fuzzy matching.** Redacting `sha256(secret)` would be easy and
  would not help: the transformation space is unbounded, and this is the
  documented boundary of the threat model, not an oversight.
- **No redaction of the request.** The agent chooses what it sends; the broker
  has nothing to hide from it there.
- **No attempt to redact the raw log.** That file exists precisely so the
  operator has the unredacted truth. It is 0600 `faramir-broker`, and the agent is
  given a `log_id` to quote instead.

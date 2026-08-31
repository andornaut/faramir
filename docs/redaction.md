# How the redactor works

[internal/redact](../internal/redact). Each stage exists for a case the stage itself does not make obvious.

## The value set is everything the keeper manages

`op run`, `chamber exec` and `sops exec-env` mask the values *they* injected. A credential reaches the output by paths no injector knows about: a managed host printing its own configuration over `ssh` emits the password in the sops file whether or not that ref was injected, and a grep across a log file finds one written weeks ago.

So the broker holds every managed value, not the subset the current command names. It refetches:

- on startup
- when a file's fingerprint changes
- when the previous fetch could not reach the keeper. The files are unchanged in that case, so the poll would never notice, and an empty value set redacts nothing

The fingerprints come from the keeper rather than from a stat, because the secrets are group-readable by the keeper alone. The managed store globs are expanded there per request, so a file dropped into the secrets directory is picked up within a second, with no daemon to restart.

`[[secret.link]]` values are in the same set, on a different clock:

Source | When it is re-read
--- | ---
the managed store | At most once a second, [not a key](configuration.md#what-is-not-a-key-at-all), and checked when a command arrives rather than on a timer, so an idle host makes no round trip
a linked file | **Every** request. The file is the operator's own and this uid can stat it, so nothing is saved by waiting

The difference is deliberate. A linked file changes when another tool rotates the credential, which is not something the operator schedules, and a value missing from the redactor for up to a minute is a window nobody chose. That is what linking is for: the file is one the agent could read directly, and a value in the set is one a brokered command cannot print in the clear.

## Why a PTY and not a pipe

Programs behave differently when stdout is not a terminal: colour, progress meters and buffering all change. More to the point, **a process can write straight to `/dev/tty`**, which no stdout redirection sees; `ssh` and `sudo` do it for password prompts.

The child gets a PTY for stdout and stderr and no controlling terminal, so `/dev/tty` cannot be opened at all and a prompt falls back to stderr, which the redactor is reading. `internal/execserver` pins the failed open and that stderr is still captured; the end-to-end suites pin the same open failing on a real host (`check-ssh.sh`) and stderr coming back as a token (`check-wrap.sh`).

The broker creates the pair, passes the *slave* over `SCM_RIGHTS` and keeps the master, so redaction runs with no extra hop. Stdin is `/dev/null`, an immediate end of input rather than the block a child reading the PTY would meet, nothing writing to the master. What a caller pipes in with `-i` goes on a pipe of its own instead of on the PTY, feeding the program's stdin alone, so a credential prompt is still unanswerable. Cost: stdout and stderr arrive merged.

## The pipeline, in order

The first four run in this order, and each assumes the one before it has run. The last two are properties of the matcher the first four use.

**1. Strip ANSI escapes.** A colour code spliced into a value defeats matching while rendering identically (`hunte\x1b[32mr2-correct-horse`). The response carries the stripped text. An escape can split across two reads, so a bounded trailing partial sequence is held back.

Escapes only. A zero-width separator spliced between the characters (`U+200B`, `U+200D`, `U+2060`, `U+00AD`) renders identically too and is not removed, so a value written that way is not matched. Two reasons. Those characters are ordinary text in the languages that use soft hyphens and joiners, so stripping them would corrupt real output. And writing a value that way takes deliberate crafting, which puts it in the same class as `| rev`.

This stage has a second reader. CSI, OSC and the C0 controls go here, which is why an escalation prompt and `faramir logs` are not full of them. What it leaves is a bare `\r` (only CRLF is normalised), `ESC` followed by a byte outside `@-Z` and `\-_` except the `ESC (`/`ESC )` charset selections, which are stripped, and the C1 controls `U+0080` to `U+009F`, the patterns matching CSI as `ESC [` while `U+009B` is the single-character form of the same introducer. [internal/termsafe](../internal/termsafe/termsafe.go) renders all three before any reaches a terminal, so narrowing what is stripped here widens what termsafe has to catch.

**2. Match an expanded value set.** Not exhaustive by design: an agent that *wants* to defeat this can. These are what ordinary tools produce by accident.

Variant | Produced by
--- | ---
raw | anything
base64, padded and unpadded | `\| base64`, JSON payloads, `Authorization: Basic`
base64 URL-safe, padded and unpadded | JWTs, signed URLs
base32, padded and unpadded | TOTP seeds, `otpauth://` URIs, some token formats
hex, lower and upper case, contiguous | `xxd -p`, `hexdump -ve '/1 "%02x"'`, Python's `bytes.hex()`, hex BLOB columns
percent-encoded, in the `quote(safe="")`, `encodeURIComponent` and `encodeURI` safe sets, each in upper and lower hex, and with `%20` or `+` for a space | any URL or form body carrying a credential
JSON string-escaped leaving non-ASCII as UTF-8, and with `\/` | `-vvv` output, API responses, Go's `encoding/json`, `json.dumps(ensure_ascii=False)`
shell single-quoted, both the `'\''` and `'"'"'` escapes | `set -x` traces, Python's `shlex.quote`
shell double-quoted (`\\`, `\$`, `` \` ``, `\"`) | `set -x` traces
every variant above of the value as stage 1 would leave it, where that stripped form still clears the policy | a stored value carrying a CRLF, a control or an escape, which never appears in output the way it appears in the store

Outside it: JSON that escapes non-ASCII to `\uXXXX`, which is what `json.dumps` and PHP's `json_encode` do by default. A value whose characters are all ASCII is unaffected, because that escaping has nothing to change; one carrying any other character is matched in neither the escaped form nor the raw one.

Outside it and always will be: backslash re-quoting, whether from `printf %q` or Python's `repr`, and any deliberate transform (`\| rev`, `\| tr a-z A-Z`, a hash), because the child chooses its own output encoding.

The hex row is the contiguous rendering, one byte after another. A dump that separates the bytes is a different string and is not covered: `od -An -tx1` and `hexdump -C` space them, `hexdump` with no arguments writes byte-swapped 16-bit words, and `openssl x509 -text` colons them. What they have in common is a separator chosen by the tool, which is the same unbounded space the paragraph below describes.

HTML and XML entity escaping is outside it deliberately. Every encoding above has one spelling or a closed set of them, which is what makes enumerating it possible. Entity escaping has a named, a decimal and a hexadecimal form per character, and the encoder chooses which characters to escape at all, so `&#112;` for a plain `p` is as valid as leaving it alone: a list of renderings would cover whichever producer it was written against and read as covering the rest.

**3. A wrapped rendering needs a second pass.** `base64` wraps at 76 columns, and `fold` wraps the raw value and every other variant the same way, so the rendering arrives with newlines inside it and matches nothing line by line. The redactor matches the whole variant set against a view with the line breaks removed and maps hits back to spans in the original; a guard keeps this pass to matches that genuinely straddle a break.

Line breaks are all that is removed, `\n` and a bare `\r`. A continuation the formatter **indents** keeps its leading whitespace between the fragments and is not caught: `pr`, and the nested fields of `openssl -text`, wrap that way. Collapsing indentation as well would join any two words straddling an indented break, corrupting more output than the wrapping it would catch.

Cost: a low-entropy value split across a line break can be redacted where its two halves were unrelated words. That fails toward redaction rather than toward a leak, as the length gate does. The token replaces the whole span including the break, so such a match also joins the two lines: with `password` managed, `"the pass\nword list is here"` comes back as `"the «SECRET:ref» list is here"`.

A value that **already** spans lines is the reverse case and needs the reverse treatment. Section 3 rejoins a value one formatter broke apart; this is a value that arrived with newlines of its own, whose lines a tool then separates. The whole value matches only while its lines stay adjacent, and ordinary tools do not keep them adjacent:

| What the tool does | Between the lines |
| --- | --- |
| `cat -n`, `nl` | a line number and a tab |
| `grep -n` | a line number and a colon |
| `sed 's/^/    /'` | the indent it adds |
| `sed -n 2p` | nothing: one line is printed and the other never is |
| unquoted `$VAR` | one space, word splitting having eaten the newline |

None of those is an attempt to defeat redaction, which is why they are matched rather than accepted. Two additions cover them. Each line of a multi-line value is registered as a rendering of its own, which is what every route above leaves intact whatever it puts between them. The whole value is registered again with its newlines rewritten to the separators a shell or a formatter substitutes, which is redundant with the per-line needles for most values and is the only cover for one whose lines are each too short to register.

Cost: a line under `[secret] min_length` is not registered on its own, so a multi-line value can be partly covered. That is the gate a short single-line value already meets. A value whose every line is short is matched only where its lines arrive adjacent.

**4. What stage 1 removed needs a second pass too.** A CSI sequence ends at the first byte in `@-~`, which is every letter and most punctuation. So a value written straight after an introducer that never got its own terminator supplies that terminator itself: `ESC [` before `hunter2` is a sequence ending in `h`, and the stripped text stage 2 would otherwise see reads `unter2`, which matches nothing.

Nothing in the bytes tells that apart from a real `ESC [ 3 2 h`, so the strip is correct and the miss belongs to stage 2, which has only the stripped text to look at. The redactor matches a second view, one holding the last byte of every CSI back where it was, and maps hits onto the emitted text. A real sequence leaves a stray letter in front of the value in that view, which no match cares about. Only the case that view alone can find is taken, so text carrying no escapes is still scanned once.

It is only CSI. Every other sequence stage 1 removes ends on a byte a value cannot have supplied: OSC and DCS on `BEL` or `ST`, the two-character escapes on the byte the introducer already named, a stray control on itself.

`run` merges stdout and stderr onto one PTY, so this shape arrives without anybody writing it: a partial colour sequence on one stream lands directly before a credential on the other.

**5. Stream with an overlap buffer.** A tail of the longest rendering plus 16, counted in non-newline runes, is held back on every `Feed` and released on `Flush`. Counting non-newline runes covers base64 line wrapping, which puts newlines inside a value: a rendering wrapped across any number of lines is held until all of its own characters have arrived. The 16 is slack for a reinserted escape byte and for quoting expansion at a chunk boundary. The tail is held raw and unredacted, so an escape that ate a value's first byte is re-stripped with the rest of the value on the next chunk; a match is counted only where it lands in an emitted prefix, so re-scanning the tail cannot double-count, and a streamed redaction is byte-identical to a one-shot one. Two bounds on the hold: a chunk ending inside a multibyte rune keeps the partial bytes until the rest arrives (or `Flush`, counted as invalid), and the whole hold is capped at about a million runes, so a flood of blank lines cannot grow it without limit. A rendering padded past that cap is emitted rather than held, and is not caught once wrapped.

The buffer only covers a join it is on both sides of, so **one redactor has to span the whole of a stream**. The broker keeps one for the PTY it is reading; `faramir redact` gets it by sending every chunk of one input down one connection, which is what [`more`](protocol.md#redact-and-streaming-it) is for.

A streaming `faramir redact` sends a chunk when it has a chunk's worth or after a short idle: without the idle, a backgrounded command that prints a line and then waits would hold that line until it produced a whole chunk or exited, which for a dev server is never. The idle chunk is still marked `more`, so the broker keeps holding the tail; only the last chunk releases it.

**The idle flush bounds when a chunk is sent, not when its bytes appear.** What comes back is everything outside the tail, and the tail is the longest rendering plus a margin: hex doubles a value's length and percent-encoding can triple it, so the window is two to three times the longest managed value. A stream trails by that many characters however slowly it produces them, and one that never produces that many shows nothing until it ends. **How far a stream lags is set by the longest value the host manages**, not by the flush interval:

Longest managed value | A stream printing one 30-byte line a second | One 300-byte line a second
--- | --- | ---
~46 B | starts after a few lines, then trails by about four | arrives as it is printed
4 KiB | minutes behind | about half a minute behind

That is the bound on `wrap.sh --stream`, which is the path a backgrounded command takes, and on the `redact` guarantee that a broker lost mid-stream truncates rather than empties: below the tail there is nothing yet released to keep. One long value is enough to set it for every stream on the host, so a multi-line key, a PEM, or a `[[secret.link]]` read as `text` is worth keeping out of the managed set where the value can be held some other way.

**6. Minimum length gate.** A short password redacts unrelated output at random: if `cat` is a secret, "concatenate" gets mangled. [`[secret] min_length`](configuration.md#what-a-flag-sets) is the floor, and a value under it is **refused at load**: not held, not listed, not injectable.

That floor is a length, not an entropy. An ordinary word clears it and still redacts unrelated output, so a ref holding `production` turns that word into a token wherever it appears and a working command reads as broken. It is also guessable by position, the agent choosing the text a substitution lands in, which is [the oracle](design.md#what-this-gives-up) arriving through the redactor rather than around it. Usernames, hostnames and path components are rarely the secret: keep them out of the managed set.

There is a ceiling too, and it is a cost rather than a setting. Every value enters an automaton whose states carry a dense transition table, so the set costs roughly 15 KB of the broker's memory per byte of secret. A value at or over **16 KiB** is refused at load for that reason: 16 KiB of secret already costs about 240 MB, one at the kernel's cap would take the broker past 1.9 GB on its own, and a broker the host kills is a host where nothing is redacted until it comes back. The kernel's own limit sits above it, Linux capping one environment variable at 128 KiB, so nothing this holds is a value it could not inject.

16 KiB is above every credential this is for: an SSH private key, a TLS chain, a kubeconfig with its embedded CAs, any API token. A credential larger than that is a file rather than a value, and [`faramir block add --path`](operating.md#operator-commands) is the arrangement for it: refused to the agent's file tools, still readable by a brokered command. `faramir link` is not the way around the cap, a linked value entering the same automaton.

The other half of the same bound is on the broker's unit: `MemoryMax` holds it to a share of the machine, so a value **set** that has outgrown the host kills the broker rather than leaving the host's OOM killer to pick something else. `faramir doctor` reports what it is holding against that, so a store growing towards it is seen before it is met.

Length is nearly the whole of the test. There is no distinct-character count and no entropy floor: neither is the strength check it reads as (`password` clears both), and how strong a credential is belongs to whoever chose it. Length is a bound on what the redactor can search for without eating the output. A long low-entropy value such as `aaaaaaaa` matches any run of eight, but that mangles the operator's own output rather than letting a value escape. The one non-length refusal is a value shaped like faramir's own `«SECRET:…»` token, which the redactor emits and would re-wrap; no real credential is that shape.

Refusal closes the injection half only. A refused value is absent from the redactor, so if it reaches the output by another route it arrives in plaintext. That is why the list stays operator-side: the broker logs each one at load and `faramir broker --check` reports them under `secrets.not_redactable` and exits non-zero, while `faramir status` and `faramir refs` say nothing. Lengthen the secret rather than lowering the threshold.

**7. Stable tokens.** The same secret is always `«SECRET:home/router/admin»`, in every response and session. Two refs holding the same value share one token, the redactor deduplicating by value and keeping the first ref by name, so which name it is does not move between restarts. Guillemets because they essentially never occur in tool output.

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

# Adversarial assessment: where faramir's safety holds and where it ends

An adversary's-eye pass over faramir, run against a real broker/executor/keeper
in a temp dir (single uid) plus a static audit of the uid boundary from the
systemd units and socket code. Reproducers ship as:

- `internal/redact/adversarial_test.go` — `go test ./internal/redact -run TestAdversarialBattery -v`
- `internal/e2e/adversarial_test.go` — `go test -count=1 ./internal/e2e -run TestAdversarialE2E -v`

The headline: **the hard boundary (the uid separation that keeps the age master
key and plaintext out of the agent's reach) holds. The soft boundary
(redaction) is where the edge is, and it is closer in than the top-level README
rows read.**

## Status: the accidental-encoding gaps are now closed

Everything in §2 that was an *accidental* leak has been fixed on this branch
(`internal/redact/redact.go`); the reproducers now assert redaction instead of
observing a leak. What changed:

- **hex (both cases), base32, HTML/XML entities, and PHP-style JSON `\/`** are
  now in the variant set.
- **The newline-collapsing pass runs over the whole variant set**, not base64
  alone, so a raw value a formatter wrapped across lines is reassembled and
  caught. A guard limits it to matches that genuinely straddle a line break.
- `docs/redaction.md` documents the expanded set and the one tradeoff (a
  low-entropy value split across a line can be over-redacted -- never leaked).

What is left leaking is only the **deliberate** class the threat model already
disclaims: `printf %q` re-quoting, `| rev`, `| tr a-z A-Z`, hashing. Those are
unbounded and out of scope by design. `set -x` was checked and was already
covered. The rest of this document is the original assessment, for the record.

## 1. The hard boundary holds

I could not find a path from a brokered command back to the master key or to
another account's plaintext. The construction is sound:

- **Peer auth is `SO_PEERCRED`** (`internal/sockutil`), which the kernel fills
  in — a caller cannot forge its uid/gid. The keeper admits only the broker
  account (plus root and keeper-self); the executor's uid is rejected there.
- **The age key never reaches a uid that executes anything.** It is delivered to
  the keeper via `LoadCredential=` (readable at `$CREDENTIALS_DIRECTORY` by the
  keeper uid alone), the file is `0400 faramir-keeper`, and the broker unit
  carries *no* `LoadCredential=`, so no brokered child shares a uid that can
  read it. This is "master key loss — prevented" holding by construction, as the
  README claims.
- **`ProtectProc=invisible` + `ProcSubset=pid`** on the broker and executor stop
  the agent uid from reading `/proc/<pid>/environ` of the broker or of a sibling
  command — the passive-discovery vector.
- **Defence in depth on the internal sockets**: `SocketMode=0660` with
  `SocketGroup=<broker>` *and* a handler-side account check. Filesystem and
  application layer would both have to fail.
- **SSH keys are usable but not extractable**: the child gets `SSH_AUTH_SOCK`,
  the broker relays only `REQUEST_IDENTITIES`/`SIGN_REQUEST`. The child can
  authenticate as you (documented "blast radius", out of scope) but cannot read
  the private key.

Caveat on method: this environment is single-uid, so these are audited from the
unit files and the peer-auth code, not exercised across real uids. `sudo faramir
doctor` on a real host is what proves them live. Nothing in the audit
contradicts the design; the boundary is genuinely the strong part.

## 2. The soft boundary: redaction leaks common, non-adversarial encodings

Redaction is a blocklist of output encodings against an unbounded space, and the
project says so plainly ("an agent that *wants* to defeat this can"). That is not
the finding. The finding is that the **uncovered set includes encodings ordinary
tools emit with no adversarial intent**, which sits in tension with the two
README rows that read as broad guarantees:

- *Accidental disclosure … Prevented … output is redacted before the agent sees it.*
- *Casual prompt injection … Prevented … the agent process never holds them.*

The agent never holding the value does not help when the **brokered command's
output** carries a recoverable encoding of it. Confirmed end-to-end through the
real broker (`redactions=0` — the broker never even recognised a secret):

| Encoding | Produced by (ordinary) | Result |
|---|---|---|
| **hex, lower/upper** | `xxd -p`, `od -An -tx1`, `hexdump`, `openssl`, DB BLOB dumps, fingerprints | **LEAKED** |
| **raw value line-wrapped** | `fold`, `fmt`, `pr`, `openssl x509 -text`, width-aware pretty-printers | **LEAKED** |
| **base32** | TOTP seeds, some token formats | **LEAKED** |
| **HTML entities** | an API's HTML error page reflecting a token, fetched with `curl` | **LEAKED** (secrets with `& < >`) |
| **PHP-style JSON `\/`** | `json_encode` and many JSON APIs escaping `/` | **LEAKED** (secrets containing `/`, e.g. base64/bcrypt) |
| base64 (control) | `\| base64` | redacted ✓ |

### The sharpest one: hex

`hex` is not exotic. Displaying key material as hex is routine — `openssl`,
`xxd`, `hexdump`, fingerprints, hex-encoded columns. Because there is **no hex
variant anywhere in the redaction path** (`internal/redact/redact.go` handles
raw, base64 std/URL padded/unpadded, percent, JSON-escape, and two shell-quote
forms — grep confirms only `base64.EncodeToString`), a one-line command like

```
faramir run --env T=secret://svc/token -- bash -lc 'printf %s "$T" | od -An -tx1'
```

returns the secret in full, tokenised nowhere. That is a **single common
encoder, not a transform pipeline** — which is what makes it bite the "casual
prompt injection is prevented" claim. A casual injection that says "verify the
token with `xxd`" recovers it.

### The architecturally interesting one: line-wrapped raw

The redactor already contains the machinery to defeat line-wrapping
(`collapsedView` collapses `\n`/`\r` and maps matches back) — but it is wired
**only to the base64 pattern** (`subWrapped` consults `e.wrapped`, which is
`base64Variants` only). So a *raw* secret split by newlines — no transform at
all, just wrapping by a formatter — is not reassembled and leaks. The defence
exists; it just doesn't cover the raw value it was built around.

### One I checked and it is NOT a gap

`set -x` (bash xtrace) — the README claims it is covered. Verified against real
bash 5.2: xtrace uses single-quoting (`'p@ss…&x…'`, and `'a'\''b'` for embedded
quotes), both of which the variant set catches. The claim holds. Only `printf
%q`'s backslash form (`v\&x\<y\>z`) escapes, which is a narrower and more
deliberate case.

## 3. Recommendations, in priority order (all done on this branch)

1. ~~**Add hex (both cases) to the variant set.**~~ Done. Cheapest, highest-value
   fix; closes the most common accidental-disclosure vector.
2. ~~**Extend `collapsedView` matching to all variants, not just base64.**~~ Done
   — the wrapped pass now runs the full variant set against the newline-free
   view, closing the line-wrap leak, with a line-break guard against false
   positives.
3. ~~**Consider base32 and HTML-entity encoding.**~~ Done, plus PHP-style JSON
   `\/`.
4. ~~**Tighten the docs so the guarantee matches the code.**~~ Done in
   `docs/redaction.md`: the variant table now lists the added encodings and the
   line-wrap paragraph states it covers all variants and names its one tradeoff.
   The top-level README "Prevented" rows now hold as written, since the code
   caught up to them rather than the reverse.

None of this changes the threat model's core, correct claim: an agent that wants
to exfiltrate can, and the uid boundary is the real containment. The value here
is pulling several *accidental* encodings out of the "adversarial, out of scope"
bucket where they currently, implicitly, sit.

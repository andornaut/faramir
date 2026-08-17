#!/bin/bash
# The leak hunt.
#
# The guard refuses what someone thought to name; the wrapper is what covers
# everything else.  So the question that decides whether any of this works is
# narrow: given output that contains a secret, in whatever shape the program
# that printed it chose, does the value reach the transcript?
#
# Every rendering below is produced by a real tool, not by restating the
# redactor's own variant list, and every one goes through the running broker.
set -u
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

# Exported, not just set: several producers below are python reading
# os.environ, so that the value is never interpolated into a program's source
# where a quote in it would change the program.
export SECRET='hunter2-correct-horse-battery'
TOKEN='«SECRET:db/password»'
PIN='8341'

# redact runs the real client against the running broker, as the agent's uid.
redact() { runuser -u op -- /usr/local/bin/faramir redact; }
# leaks reports whether the redacted form still contains the value.
leaks() { grep -qF "$SECRET"; }

# --------------------------------------------------------------------------
head_ "1. the shapes a program prints a value in by accident"
# Each rendering is produced by the tool that actually produces it, so this
# asserts against the encodings in the world rather than against the list the
# redactor was written from.
try() { # label producer
  local label=$1 out
  out=$(eval "$2" | redact)
  if grep -qF "$TOKEN" <<<"$out"; then ok "$label"
  else bad "$label: not redacted -> $(head -c 90 <<<"$out")"; fi
}
try "the value as it stands"          "printf '%s\n' \"\$SECRET\""
try "base64 (coreutils)"              "printf '%s' \"\$SECRET\" | base64"
try "base64, unwrapped"               "printf '%s' \"\$SECRET\" | base64 -w0"
try "base64 url-safe, unpadded"       "python3 -c \"import base64,os;print(base64.urlsafe_b64encode(os.environ['SECRET'].encode()).decode().rstrip('='))\""
try "base32 (a TOTP seed's encoding)" "printf '%s' \"\$SECRET\" | base32"
try "hex, lower (xxd -p)"             "printf '%s' \"\$SECRET\" | xxd -p"
try "hex, upper"                      "python3 -c \"import os;print(os.environ['SECRET'].encode().hex().upper())\""
try "percent-encoded (urllib.quote)"  "python3 -c \"import urllib.parse,os;print(urllib.parse.quote(os.environ['SECRET'],safe=''))\""
try "percent-encoded, plus for space" "python3 -c \"import urllib.parse,os;print(urllib.parse.quote_plus(os.environ['SECRET']))\""
try "inside a JSON document"          "python3 -c \"import json,os;print(json.dumps({'pw':os.environ['SECRET']}))\""
try "shell-quoted (shlex.quote)"      "python3 -c \"import shlex,os;print(shlex.quote(os.environ['SECRET']))\""
try "inside a shell double-quote"     "printf '%s\n' \"\\\"\$SECRET\\\"\""
try "no separator around it"          "printf 'prefix%ssuffix\n' \"\$SECRET\""
try "repeated on one line"            "printf '%s %s %s\n' \"\$SECRET\" \"\$SECRET\" \"\$SECRET\""

head_ "2. mangled on the way out"
# A value the printing program broke up or coloured in.
out=$(printf '%s' "$SECRET" | fold -w 6 | redact)
grep -qF "$TOKEN" <<<"$out" && ok "split across lines by a formatter (fold -w 6)" \
  || bad "line-split value leaked: $(tr '\n' '/' <<<"$out")"
out=$(printf '\033[31m%s\033[0m\n' "$SECRET" | redact)
grep -qF "$TOKEN" <<<"$out" && ok "wrapped in colour codes" || bad "coloured value leaked: $out"
out=$(python3 -c "
import os,sys
s=os.environ['SECRET']
sys.stdout.write(s[:10]+'\033[1;32m'+s[10:20]+'\033[0m'+s[20:]+'\n')" | redact)
grep -qF "$TOKEN" <<<"$out" && ok "with escape sequences spliced into the middle of it" \
  || bad "value with interior escapes leaked: $out"
out=$(printf '%s\r\n' "$SECRET" | redact)
grep -qF "$TOKEN" <<<"$out" && ok "with CRLF line endings" || bad "CRLF leaked: $out"

head_ "3. where in the stream it sits"
# The redactor holds back a tail so a value split across two reads is still
# caught.  These put the value exactly where the seam would be.
#
# `faramir redact` breaks its input into 32KiB requests, on a newline where it
# can.  A line longer than that is broken mid-line, and each request is answered
# by its own redactor, so the held-back tail does not span the break: a value
# that straddles it is not redacted, exit status 0, output byte-identical to
# input.  The offsets below sit on that seam.
for offset in 1 1023 4095 8191 32740 65508; do
  out=$(python3 -c "
import os,sys
pad=os.environ['SECRET']
sys.stdout.write('.'*$offset + pad + '.'*100 + '\n')" | redact)
  if grep -qF "$TOKEN" <<<"$out"; then ok "at byte offset $offset"
  else bad "LEAKED at offset $offset"; fi
done
# At the very end, with nothing after it: the held-back tail has to be flushed.
out=$(printf '%s' "$SECRET" | redact)
grep -qF "$TOKEN" <<<"$out" && ok "as the last bytes of the stream, no newline" \
  || bad "the tail was not flushed: [$out]"
# And a prefix of the value at EOF must be released, not held forever.
out=$(printf 'trailing hunter2-corr' | redact)
[ "$out" = "trailing hunter2-corr" ] && ok "a partial value at EOF is released unchanged" \
  || bad "a partial match was held back or mangled: [$out]"
# The seam is only reached on a line longer than a chunk: with a newline before
# the value the chunker breaks there instead, which is the ordinary case and
# what makes the gap above easy to miss.
out=$(python3 -c "
import os,sys
sys.stdout.write('.'*32740 + '\n' + os.environ['SECRET'] + '.'*200 + '\n')" | redact)
grep -qF "$TOKEN" <<<"$out" && ok "the same offset with a newline before it is redacted" \
  || bad "even a newline-delimited value leaked at the chunk offset"
# The PTY path is one redactor over the whole stream, so it has no such seam.
out=$(runuser -u op -- faramir run --quiet -t 30 --env PW=faramir://db/password -- \
  /usr/bin/python3 -c "
import os,sys
sys.stdout.write('.'*32740 + os.environ['PW'] + '.'*200 + '\n')" 2>&1)
grep -qF "$SECRET" <<<"$out" && bad "faramir run leaks at the chunk offset too" \
  || ok "faramir run has no seam at that offset: one redactor spans the stream"
# The absence above is only evidence if the value was there to redact: a run
# that failed prints an error, holds no value, and would pass it.
grep -qF "$TOKEN" <<<"$out" && ok "  and the value was injected, so the check had a subject" \
  || bad "faramir run printed no token, so the line above asserts nothing: ${out:0:120}"

head_ "4. volume"
size=$(python3 -c "
import os,sys
s=os.environ['SECRET']
block=('x'*4096+'\n')
sys.stdout.write(block*3000)
sys.stdout.write(s+'\n')
sys.stdout.write(block*3000)" | redact | tee /tmp/big.out | wc -c)
grep -qF "$TOKEN" /tmp/big.out && ok "a value buried in 24MB of output is still found" \
  || bad "the value was missed in a large stream"
grep -qF "$SECRET" /tmp/big.out && bad "and the raw value is in there too" \
  || ok "and the raw value appears nowhere in $size bytes"
[ "$(grep -c 'x\{4096\}' /tmp/big.out)" = "6000" ] && ok "and nothing else was dropped" \
  || bad "output was truncated: $(grep -c 'x\{4096\}' /tmp/big.out) blocks of 6000"

head_ "5. what it must not eat"
out=$(printf 'the word battery appears here\nand horse too\n' | redact)
[ "$out" = "the word battery appears here
and horse too" ] && ok "a word that is part of a secret is not redacted on its own" \
  || bad "ordinary text was mangled: [$out]"
out=$(printf 'hunter3-correct-horse-battery\n' | redact)
[ "$out" = "hunter3-correct-horse-battery" ] && ok "a near-miss is left alone" || bad "near-miss: [$out]"
out=$(head -c 200000 /dev/urandom | redact | wc -c)
[ "$out" -gt 0 ] && ok "binary input does not hang or empty the stream ($out bytes out)" \
  || bad "binary input produced nothing"

head_ "6. the value that is too short to redact"
# A short value matches inside ordinary words, so redacting it would blank
# unrelated output.  It is refused at load instead -- which means it is also
# never injected, and the operator has to be told, or they would assume a ref
# they can see in the file is covered.
out=$(printf 'the pin is %s\n' "$PIN" | redact)
grep -q "$PIN" <<<"$out" && ok "a value under min_length is not redacted (by design)" \
  || bad "the short value was redacted after all: $out"
refs=$(runuser -u op -- faramir list-secrets)
# A ref that is served, so an empty answer fails here rather than passing the
# absence below.
grep -q 'db/password' <<<"$refs" || bad "list-secrets answered nothing, so the check below has no subject"
grep -q 'short/pin' <<<"$refs" && bad "it is offered as an injectable ref" \
  || ok "and it is not offered as a ref that can be injected"
# The operator has to be told, or a ref they can see in the file reads as
# covered.  The agent must not be: status is answered to any member of the
# client group, so what goes in it lands in a model's context.
status=$(runuser -u op -- faramir status)
grep -q 'count' <<<"$status" || bad "status answered nothing, so the check below has no subject"
grep -q 'short/pin' <<<"$status" && bad "the agent-facing status op names a refused ref" \
  || ok "the agent-facing status op does not name it"
doctor=$(faramir doctor 2>&1)
grep -q 'short/pin' <<<"$doctor" && ok "but doctor does, so the operator is not left guessing" \
  || bad "no operator-facing surface names the refused ref"
grep -q 'shorter than' <<<"$doctor" && ok "and says why it was refused" || bad "no reason given"
check=$(faramir broker --check 2>&1)
grep -q '"short/pin"' <<<"$check" && ok "and --check reports it under not_redactable" \
  || bad "--check does not carry it"
# Asking for it by name has to be an error that explains itself, not a blank.
out=$(runuser -u op -- faramir run --env P=faramir://short/pin -- /bin/sh -c 'echo $P' 2>&1)
grep -qF "$PIN" <<<"$out" && bad "the refused value was injected anyway: $out" \
  || ok "and injecting it is refused rather than silently blank"
grep -qi 'refused\|not redactable\|cannot' <<<"$out" && ok "with a reason the caller can act on" \
  || bad "the refusal does not explain itself: $out"

head_ "7. the documented edges, pinned so a change is deliberate"
# HTML entity escaping is deliberately not covered: each character has a named,
# a decimal and a hexadecimal form and an encoder picks which to escape at all,
# so a variant list would cover one producer and read as coverage of the rest.
# docs/redaction.md says so; this asserts it still behaves that way.
entity=$(python3 -c "
import html,os
print(html.escape(os.environ['SECRET']).replace('-','&#45;'))")
out=$(printf '%s\n' "$entity" | redact)
grep -qF "$TOKEN" <<<"$out" \
  && bad "HTML entities are now redacted. That is an improvement, not a regression: move this to the covered set and say so in docs/redaction.md" \
  || ok "HTML entity escaping is still out of scope, as documented"
# A file can contain the token text; the model cannot tell that from a real
# redaction.  Not a leak, but it is what the transcript looks like.
out=$(printf 'note: the password is %s\n' "$TOKEN" | redact)
grep -qF "$TOKEN" <<<"$out" && ok "a literal token in the input passes through unchanged" \
  || bad "the token itself was rewritten: $out"
# Redacting twice must be a no-op, or the wrapper's second pass over an already
# redacted stream would corrupt it.
out=$(printf '%s\n' "$SECRET" | redact | redact)
[ "$out" = "$TOKEN" ] && ok "redaction is idempotent, so a second pass costs nothing" \
  || bad "a second pass changed the output: [$out]"

head_ "8. the same value through the other path"
# `faramir run` injects and redacts on its own PTY; the wrapper redacts a
# captured file.  A value must not be covered on one path and not the other.
out=$(runuser -u op -- faramir run --quiet -t 20 --env PW=faramir://db/password \
        -- /bin/sh -c 'echo $PW; echo $PW | base64; echo $PW | xxd -p' 2>&1)
grep -qF "$SECRET" <<<"$out" && bad "the injected value came back in the clear: $out" \
  || ok "injected, then redacted on the way back"
[ "$(grep -cF "$TOKEN" <<<"$out")" = "3" ] && ok "in all three renderings the command printed" \
  || bad "only $(grep -cF "$TOKEN" <<<"$out") of 3 renderings were caught: $out"
# And the audit log records the count without the value.
sleep 1
log=$(tail -3 /var/log/faramir/audit.log)
grep -qF "$SECRET" <<<"$log" && bad "THE AUDIT LOG CONTAINS THE VALUE" || ok "the audit log holds no value"
grep -q 'db/password' <<<"$log" && ok "it names the ref that was used" || bad "the ref is not recorded: $log"

summary

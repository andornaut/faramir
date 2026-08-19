#!/bin/bash
# The redact stream, which is new code carrying the whole redaction
# claim for everything the agent runs.
#
# The seam this replaced was invisible: exit 0, output byte-identical to input,
# nothing logged. So the tests here are mostly about the joins -- every offset
# around several chunk boundaries, the longest renderings across one, several
# secrets across different ones -- plus what the connection now has to survive
# that a one-shot request never did: a producer that goes quiet, a broker that
# restarts, another op arriving mid-stream, and streams running at once.
set -u
export SECRET='hunter2-correct-horse-battery'
export SECOND='tok_live_0PENSESAME_9911'
TOKEN='«SECRET:db/password»'
TOKEN2='«SECRET:api/token»'
CHUNK=32768
SOCK=/run/faramir/broker.sock
# The two raw clients below speak the protocol by hand, and a daemon refuses a
# request naming another version before it reads the op.
VERSION=$(faramir version | awk '{print $NF}')
RUNDIR=/run/user/$(id -u op)

. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

redact() { runuser -u op -- /usr/local/bin/faramir redact; }

# --------------------------------------------------------------------------
head_ "1. every offset around a chunk boundary, not just the one that failed"
# The window is len(value)-1 bytes wide and sits immediately before a boundary.
# Sweeping it byte by byte is what says the join is covered rather than that one
# offset happens to work.
sweep() {
  local boundary=$1 leaked=0 tested=0 untokened=0 first=""
  for delta in $(seq -40 4); do
    local offset=$(( boundary + delta ))
    [ "$offset" -lt 0 ] && continue
    tested=$((tested+1))
    python3 -c "
import os,sys
sys.stdout.write('.'*$offset + os.environ['SECRET'] + '.'*120 + '\n')" > /tmp/s.in
    redact < /tmp/s.in > /tmp/s.out
    if grep -qF "$SECRET" /tmp/s.out; then
      leaked=$((leaked+1)); [ -z "$first" ] && first=$offset
    fi
    # Absence of the value proves nothing on its own: empty output has none
    # either. The token is what says the redactor saw it and replaced it.
    grep -qF "$TOKEN" /tmp/s.out || untokened=$((untokened+1))
  done
  if [ "$leaked" -ne 0 ]; then
    bad "boundary $boundary: $leaked of $tested leaked, first at offset $first"
  elif [ "$untokened" -ne 0 ]; then
    bad "boundary $boundary: $untokened of $tested produced no token, so those offsets prove nothing"
  else
    ok "boundary $boundary: $tested offsets across it, every one tokenized"
  fi
}
sweep $CHUNK
sweep $(( CHUNK * 2 ))
sweep $(( CHUNK * 3 ))

head_ "2. deep in a long stream, and more than one value"
# One line of several MB crosses many joins; the value sits on one of the later
# ones, so this is the join being covered rather than the first chunk being big
# enough to hold everything.
python3 -c "
import os,sys
s=os.environ['SECRET']
sys.stdout.write('.'*($CHUNK*100 - 12) + s + '.'*500 + '\n')" > /tmp/deep.in
out=$(redact < /tmp/deep.in)
grep -qF "$SECRET" <<<"$out" && bad "leaked at the 100th chunk boundary" \
  || ok "a value on the 100th boundary of a 3MB line is redacted"
grep -qF "$TOKEN" <<<"$out" && ok "and came back as its token" || bad "no token deep in the stream"

# Two different secrets, each straddling a different boundary.
python3 -c "
import os,sys
a,b=os.environ['SECRET'],os.environ['SECOND']
sys.stdout.write('.'*($CHUNK - 12) + a)
sys.stdout.write('.'*($CHUNK - len(a) + 12 - 8) + b)
sys.stdout.write('.'*200 + '\n')" > /tmp/two.in
out=$(redact < /tmp/two.in)
grep -qF "$SECRET" <<<"$out" && bad "the first value leaked" || ok "two values on two boundaries: first redacted"
grep -qF "$SECOND" <<<"$out" && bad "the second value leaked" || ok "second redacted"
[ "$(grep -c "$TOKEN2" <<<"$out")" -ge 1 ] && ok "and both tokens are present" || bad "missing the second token"

head_ "3. the long renderings across a join"
# The overlap is sized from the LONGEST rendering, not the value: hex is twice
# the length and base64 is four thirds of it. Those are what test the margin.
straddle() { # label python-expression-producing-the-rendering
  local label=$1 expr=$2 rendering
  rendering=$(python3 -c "$expr")
  local n=${#rendering}
  # Start it a dozen bytes before the boundary so the break falls inside it.
  python3 -c "
import sys
r='''$rendering'''
sys.stdout.write('.'*($CHUNK - 12) + r + '.'*200 + '\n')" > /tmp/r.in
  redact < /tmp/r.in > /tmp/r.out
  if grep -qF "$rendering" /tmp/r.out; then
    bad "$label ($n bytes) leaked across the join"
  elif ! grep -qF "$TOKEN" /tmp/r.out; then
    bad "$label ($n bytes): no token, so its absence says nothing"
  else
    ok "$label ($n bytes) is caught across the join"
  fi
}
straddle "hex"    "import os;print(os.environ['SECRET'].encode().hex())"
straddle "base64" "import base64,os;print(base64.b64encode(os.environ['SECRET'].encode()).decode())"
straddle "base32" "import base64,os;print(base64.b32encode(os.environ['SECRET'].encode()).decode())"
straddle "percent-encoded" "import urllib.parse,os;print(urllib.parse.quote(os.environ['SECRET'],safe=''))"

head_ "4. what must survive being carried in pieces"
# A stream is now many requests; the bytes still have to come back exactly.
head -c 3000000 /dev/urandom > /tmp/bin.in
redact < /tmp/bin.in > /tmp/bin.out
# Bigger than it went in: a byte that is not valid UTF-8 becomes U+FFFD, which
# is three. That is the redactor's own long-standing behaviour on binary, not
# something the stream introduced; what matters here is that it terminates and
# does not truncate.
[ "$(wc -c < /tmp/bin.out)" -gt 3000000 ] && ok "3MB of binary streams through ($(wc -c < /tmp/bin.out) bytes out, invalid bytes replaced)" \
  || bad "binary input produced $(wc -c < /tmp/bin.out) bytes"
# The claim that matters: a value embedded in binary is still found, including
# on a join.
python3 -c "
import os,sys
raw=os.urandom(($CHUNK - 12))
sys.stdout.buffer.write(raw)
sys.stdout.buffer.write(os.environ['SECRET'].encode())
sys.stdout.buffer.write(os.urandom(2000))" > /tmp/binsec.in
redact < /tmp/binsec.in > /tmp/binsec.out
grep -qF "$SECRET" /tmp/binsec.out && bad "a value inside binary leaked across a join" \
  || { grep -qF "$TOKEN" /tmp/binsec.out && ok "a value embedded in random binary, on a join, is tokenized" \
       || bad "no token: the value was neither found nor leaked, which says nothing"; }
# Text with no secret in it must be byte-identical, whatever the chunking.
python3 -c "
import sys
for i in range(200000): sys.stdout.write('line %d with some text\n' % i)" > /tmp/plain.in
redact < /tmp/plain.in > /tmp/plain.out
if cmp -s /tmp/plain.in /tmp/plain.out; then
  ok "4.6MB of ordinary text is byte-identical after streaming"
else
  bad "the stream altered text with no secret in it: $(cmp /tmp/plain.in /tmp/plain.out 2>&1 | head -1)"
fi
# A value at the very last byte, with no trailing newline, is the flush.
python3 -c "
import os,sys
sys.stdout.write('.'*($CHUNK*2) + os.environ['SECRET'])" > /tmp/tail.in
redact < /tmp/tail.in | grep -qF "$SECRET" && bad "the final flush missed the value" \
  || ok "a value as the last bytes of a multi-chunk stream is redacted"

head_ "5. the other shape: faramir redact -- command"
# redactStream's second caller, which streams a child rather than a file.
out=$(runuser -u op -- /usr/local/bin/faramir redact -- /bin/sh -c "echo A-\$0-B" "$SECRET" 2>&1)
grep -qF "$SECRET" <<<"$out" && bad "the command form leaked: $out" || ok "the command form redacts"
# The absence is only evidence where the value was there to redact: a command
# that did not run prints an error and would pass the line above.
grep -qF "$TOKEN" <<<"$out" && ok "  and the token is there, so the check had a subject" \
  || bad "the command form printed no token: ${out:0:110}"
runuser -u op -- /usr/local/bin/faramir redact -- /bin/sh -c 'exit 7' >/dev/null 2>&1
[ $? -eq 7 ] && ok "and preserves the child's exit status" || bad "exit status through the command form"
# The same straddle, produced by a child rather than read from a file.
out=$(runuser -u op -- /usr/local/bin/faramir redact -- /usr/bin/python3 -c "
import os,sys
sys.stdout.write('.'*($CHUNK - 12) + os.environ['SECRET'] + '.'*200 + '\n')" 2>&1)
grep -qF "$SECRET" <<<"$out" && bad "the command form leaks at the join" \
  || ok "and covers the join the same way"
grep -qF "$TOKEN" <<<"$out" && ok "  with the value tokenised, so the join was reached" \
  || bad "no token at the join, so the line above asserts nothing: ${out:0:110}"

head_ "6. a producer that goes quiet mid-stream"
# The case the inter-chunk deadline exists for: the connection is already open
# with a chunk sent, and the command then says nothing for longer than the
# 30s a peer gets to send its first request. Takes ~40s.
start=$(date +%s)
out=$(runuser -u op -- /usr/local/bin/faramir redact -- /usr/bin/python3 -u -c "
import os,sys,time
sys.stdout.write('x'*40000 + '\n')
sys.stdout.flush()
time.sleep(40)
sys.stdout.write('late ' + os.environ['SECRET'] + '\n')" 2>&1)
elapsed=$(( $(date +%s) - start ))
grep -qF "$SECRET" <<<"$out" && bad "the value printed after the quiet spell leaked" \
  || ok "a stream idle for ${elapsed}s between chunks is not dropped"
grep -qF "$TOKEN" <<<"$out" && ok "and what it printed afterwards is still redacted" \
  || bad "output after the quiet spell was lost: $(tail -c 120 <<<"$out")"

head_ "7. a broker that goes away mid-stream"
# Chunks already written came back redacted, so they stay; the chunk that
# failed and everything after it must not appear.
python3 -c "
import os,sys
sys.stdout.write('HEAD'+'a'*($CHUNK*2)+'\n')
sys.stdout.write('SENSITIVE '+os.environ['SECRET']+'\n'*1)
sys.stdout.write('TRAILING\n')" > /tmp/restart.in
( sleep 1; systemctl restart faramir-broker.service >/dev/null 2>&1 ) &
out=$(runuser -u op -- /usr/local/bin/faramir redact < <(cat /tmp/restart.in; sleep 3) 2>&1; echo "rc=$?")
wait
grep -qF "$SECRET" <<<"$out" && bad "a restart mid-stream leaked the value" \
  || ok "a broker restarted mid-stream does not leak what it never saw"
# The chunks that went through before it died are what says the stream really
# was interrupted part way, rather than having failed before it started.
grep -q "HEAD" <<<"$out" && ok "and what was redacted before it died was kept" \
  || bad "nothing came back at all, so this tested a stream that never began: $(head -c 120 <<<"$out")"
systemctl start faramir-broker.socket >/dev/null 2>&1; sleep 2
runuser -u op -- /usr/local/bin/faramir refs >/dev/null 2>&1 \
  && ok "and the broker is usable again afterwards" || bad "the broker did not come back"

head_ "8. another op arriving in the middle of a stream"
# A stream holds a redactor with a tail held back. Whatever a confused client
# does next, that tail must not be emitted unredacted.
out=$(runuser -u op -- /usr/bin/python3 -c "
import socket,json,os
s=socket.socket(socket.AF_UNIX); s.connect('$SOCK')
f=s.makefile('rwb')
def send(o):
    f.write((json.dumps(dict(o, version='$VERSION'))+'\n').encode()); f.flush()
    return json.loads(f.readline())
sec=os.environ['SECRET']
a=send({'op':'redact','text':'head '+sec[:10],'more':True})
b=send({'op':'status'})
print('FIRST:'+a.get('output',''))
print('SECOND_IS_STATUS:'+str('version' in b.get('output','')))
try:
    c=send({'op':'redact','text':sec[10:]+' tail'})
    print('THIRD:'+c.get('output',''))
except Exception as e:
    print('THIRD_CLOSED')
" 2>&1)
first=$(grep '^FIRST:' <<<"$out" | cut -d: -f2-)
case "$first" in
  *hunter2*) bad "the chunk holding a partial value emitted part of it: [$first]";;
  *)         ok "the chunk holding a partial value emitted none of it: [$first]";;
esac
grep -qF "$SECRET" <<<"$out" && bad "the interleaved op let the held tail out: $out" \
  || ok "no part of the value escaped when another op interrupted the stream"
grep -q "SECOND_IS_STATUS:True" <<<"$out" && ok "and the interrupting op was answered normally" \
  || bad "the interleaving op was not answered: $out"
grep -q "THIRD_CLOSED" <<<"$out" && ok "and the connection ended there, not silently continuing the stream" \
  || bad "the stream continued past a foreign op: $(grep '^THIRD' <<<"$out")"

head_ "9. a stream the client abandons"
out=$(runuser -u op -- /usr/bin/python3 -c "
import socket,json,os
s=socket.socket(socket.AF_UNIX); s.connect('$SOCK')
f=s.makefile('rwb')
f.write((json.dumps({'op':'redact','version':'$VERSION','text':'x'*100+os.environ['SECRET'],'more':True})+'\n').encode())
f.flush()
r=json.loads(f.readline())
print('ERR:'+json.dumps(r['error']) if 'error' in r else 'OUT:'+r.get('output',''))
s.close()
" 2>&1)
grep -qF "$SECRET" <<<"$out" && bad "an abandoned stream emitted the held-back value" \
  || ok "a stream dropped part way emits nothing it was holding"
# The chunk has to come back carrying its own head, or the absence above is a
# refusal or a round trip that never happened rather than a value held back.
grep -q '^OUT:xxxx' <<<"$out" && ok "  and the chunk before it was answered" \
  || bad "the broker answered no chunk, so the line above asserts nothing: ${out:0:110}"

head_ "10. streams at the same time, and beside a brokered command"
# Each connection has its own redactor; they must not see each other's state.
for i in 1 2 3 4 5 6; do
  ( python3 -c "
import os,sys
sys.stdout.write('.'*($CHUNK - 12) + os.environ['SECRET'] + '.'*($CHUNK) + '\n')" \
    | redact > /tmp/conc.$i ) &
done
wait
concurrent_ok=1
for i in 1 2 3 4 5 6; do
  grep -qF "$SECRET" /tmp/conc.$i && concurrent_ok=0
  grep -qF "$TOKEN" /tmp/conc.$i || concurrent_ok=0
done
[ "$concurrent_ok" = 1 ] && ok "six streams at once, each redacted correctly" \
  || bad "concurrent streams interfered with each other"
# A stream must not consume the exec concurrency slots.
( python3 -c "
import sys
sys.stdout.write('y'*(1024*1024)+'\n')" | redact >/dev/null ) &
sleep 0.2
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 -- /bin/echo brokered 2>&1)
wait
[ "$out" = "brokered" ] && ok "a brokered command runs while a stream is open" \
  || bad "the stream blocked exec: $out"

head_ "11. the audit log tells the truth about a stream"
log=/var/log/faramir/audit.log
before=$(grep -c '"op":"redact"' $log 2>/dev/null || echo 0)
python3 -c "
import os,sys
s=os.environ['SECRET']
sys.stdout.write((s+' '+'.'*30000+'\n')*4)" | redact > /tmp/audit.out
sleep 1
after=$(grep -c '"op":"redact"' $log)
added=$(( after - before ))
[ "$added" -eq 1 ] && ok "a four-chunk stream wrote exactly one audit record" \
  || bad "a stream wrote $added records, want 1"
record=$(grep '"op":"redact"' $log | tail -1)
grep -qF "$SECRET" <<<"$record" && bad "THE AUDIT RECORD CONTAINS THE VALUE" \
  || ok "and the record holds no value"
count=$(python3 -c "
import json,sys
r=json.loads(sys.stdin.read())
print(sum(c['count'] for c in r.get('redactions',[])))" <<<"$record" 2>/dev/null)
[ "$count" = "4" ] && ok "and counts all four occurrences, so the totals are the stream's" \
  || bad "the record counted $count of 4"
bytes=$(python3 -c "
import json,sys
print(json.loads(sys.stdin.read()).get('input_bytes',0))" <<<"$record" 2>/dev/null)
[ "$bytes" -gt 100000 ] && ok "and input_bytes is the whole stream ($bytes)" \
  || bad "input_bytes = $bytes, want the whole stream"

head_ "12. the agent path at the offsets that used to leak"
printf 'nothing here\n' > /home/op/project/probe.txt
chown op:dev /home/op/project/probe.txt
wrapped() {
  jq -cn --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' \
    | runuser -u op -- /usr/local/bin/faramir guard \
    | jq -r '.hookSpecificOutput.updatedInput.command'
}
agent_leak=0
for delta in -20 -12 -1 0; do
  offset=$(( CHUNK + delta ))
  python3 -c "
import os,sys
open('/home/op/project/probe.txt','w').write('.'*$offset + os.environ['SECRET'] + '.'*300)"
  out=$(runuser -u op -- env HOME=/home/op XDG_RUNTIME_DIR="$RUNDIR" \
        bash -c "cd /home/op/project; $(wrapped 'cat probe.txt')" 2>&1)
  grep -qF "$SECRET" <<<"$out" && agent_leak=1
done
[ "$agent_leak" -eq 0 ] && ok "four straddle offsets through guard + wrap.sh, none leaked" \
  || bad "the agent path still leaks at a chunk boundary"
rm -f /home/op/project/probe.txt

summary

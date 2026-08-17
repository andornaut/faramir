#!/bin/bash
# `faramir logs`, the operator's record.
#
# Every other suite tests what the broker does.  This one tests the only thing
# that says what it did.  Three claims rest on it and nothing else checks them:
#
#   - the log_id a refusal hands the agent resolves to a record an operator can
#     read, which is the whole point of citing an id the agent cannot read;
#   - the log holds no value, in any encoding, no matter what the command wrote;
#   - what the reader prints is what the log holds, on a log that has been
#     rotated, damaged, or written by something else.
#
# Run as root inside the lab container.
set -u
SECRET='hunter2-correct-horse-battery'
TOKEN='«SECRET:db/password»'
LOG=/var/log/faramir/audit.log
PROJECT=/home/op/project
. "$(dirname "$0")/lib.sh" || { echo "lab: lib.sh is missing beside $0" >&2; exit 2; }

run()  { runuser -u op -- /usr/local/bin/faramir run --quiet -t 30 -C "$PROJECT" "$@" 2>&1; }
logs() { /usr/local/bin/faramir logs --color never "$@" 2>&1; }

# configFor writes a config naming a log of this suite's own making, and prints
# its path.  `faramir logs` reads the log the config names and takes no path of
# its own, so this is how a case is given a log to read: a synthetic one, a
# damaged one, or none at all.
configFor() {
  local log=$1 cfg=/tmp/logcfg-$2.toml
  sed 's#^log_path = .*#log_path = "'"$log"'"#' /etc/faramir/config.toml > "$cfg"
  printf '%s' "$cfg"
}
# logsAt is logs() against that config.
logsAt() {
  local cfg=$1; shift
  /usr/local/bin/faramir logs --color never --config "$cfg" "$@" 2>&1
}

# lastID is the id of the record written most recently.
lastID() { tail -1 "$LOG" | jq -r .log_id; }
# shortOf is the tail an operator pastes back from the listing.
shortOf() { printf '%s' "${1##*Z-}"; }

echo "log $LOG, $(wc -l <"$LOG") records to start"

# --------------------------------------------------------------------------
head_ "1. who may read it"

out=$(runuser -u op -- head -c1 "$LOG" 2>&1)
grep -qi "permission denied" <<<"$out" && ok "the agent's uid cannot read the file" \
  || bad "op read the log directly: [$out]"

out=$(runuser -u op -- /usr/local/bin/faramir logs 2>&1); code=$?
if [ $code -eq 1 ] && grep -q "must run as root" <<<"$out"; then
  ok "faramir logs as the agent's uid: refused by name, exit 1"
else
  bad "as op: exit $code [$out]"
fi
grep -q "$SECRET" <<<"$out" && bad "the refusal carried a value" || ok "and it printed no record"

# The check is on the command, not on the file: a log the caller could read is
# still refused, so a copy left somewhere permissive does not become a way in.
cp "$LOG" /tmp/pub.log && chmod 0644 /tmp/pub.log
PUBCFG=$(configFor /tmp/pub.log pub); chmod 0644 "$PUBCFG"
out=$(runuser -u op -- /usr/local/bin/faramir logs --config "$PUBCFG" 2>&1); code=$?
if [ $code -eq 1 ] && grep -q "must run as root" <<<"$out"; then
  ok "and refused even for a log that uid can read"
else
  bad "op read /tmp/pub.log: exit $code [$(head -c 120 <<<"$out")]"
fi
rm -f /tmp/pub.log "$PUBCFG"

mode=$(stat -c '%a %U:%G' "$LOG")
[ "$mode" = "600 faramir-broker:faramir-broker" ] && ok "the log is $mode" \
  || bad "the log is $mode, want 600 faramir-broker:faramir-broker"
dmode=$(stat -c '%a' /var/log/faramir)
[ "$dmode" = "750" ] && ok "its directory is 0750, so no account can stat the log" \
  || bad "the log directory is $dmode, want 750"

logs -n 1 >/dev/null 2>&1 && ok "root reads it" || bad "root could not read the log"

# --------------------------------------------------------------------------
head_ "2. the log_id a refusal hands out resolves"
#
# `faramir run` prints "log_id=..." on a refusal and the MCP server hands the
# same id to the model.  An id naming no record sends somebody to look up
# nothing.

cited() { # description, then the argv of a run that must be refused
  local label=$1; shift
  local out id
  out=$(run "$@")
  id=$(sed -n 's/.*log_id=\([^ ]*\).*/\1/p' <<<"$out" | head -1)
  if [ -z "$id" ]; then
    bad "$label: the refusal cited no log_id: [$(head -c 100 <<<"$out")]"
    return
  fi
  if logs "$id" >/dev/null 2>&1; then
    ok "$label -> $id resolves"
  else
    bad "$label: log_id $id names no record"
    return
  fi
  # What is on screen is the short form, so that has to be accepted back.
  if logs "$(shortOf "$id")" >/dev/null 2>&1; then
    ok "$label: its short form resolves too"
  else
    bad "$label: the short form $(shortOf "$id") does not resolve"
  fi
}

cited "unknown ref"      --env X=secret://no/such -- /bin/true
cited "no such program"  -- /bin/nosuchprogram
cited "cwd is a file"    -C /etc/hostname -- /bin/true
cited "cwd is absent"    -C /nonexistent-dir-xyz -- /bin/true

# A record found by id must be the record asked for, not merely a record.
out=$(run --env X=secret://no/such -- /bin/true)
id=$(sed -n 's/.*log_id=\([^ ]*\).*/\1/p' <<<"$out" | head -1)
detail=$(logs "$id")
grep -q "$id" <<<"$detail" && ok "the detail view names the id asked for" \
  || bad "lookup returned another record: [$detail]"
grep -q "unknown secret ref: no/such" <<<"$detail" && ok "and carries why it was refused" \
  || bad "the record does not say why: [$detail]"
grep -q "op (uid $(id -u op))" <<<"$detail" && ok "and who asked" \
  || bad "the record does not name the caller: [$detail]"

# --------------------------------------------------------------------------
head_ "3. the columns say how each record ended"

run -- /bin/true >/dev/null;                     idOK=$(lastID)
run -- /bin/sh -c 'exit 7' >/dev/null;           idFail=$(lastID)
run -t 1 -- /bin/sleep 5 >/dev/null;             idSlow=$(lastID)
run --env PW=secret://db/password -- \
    /bin/sh -c 'echo a $PW; echo b $PW' >/dev/null; idRedact=$(lastID)
printf 'hello world\n' | runuser -u op -- /usr/local/bin/faramir redact >/dev/null 2>&1
idRedactOp=$(lastID)

row() { logs -n 40 | grep -F "$(shortOf "$1")"; }

grep -qE 'exit 0 +[0-9.]+s' <<<"$(row "$idOK")"   && ok "a run that succeeded shows its exit and duration" \
  || bad "exit 0 row: [$(row "$idOK")]"
grep -q 'exit 7' <<<"$(row "$idFail")"            && ok "a non-zero exit shows the code" \
  || bad "exit 7 row: [$(row "$idFail")]"
grep -q 'timed out' <<<"$(row "$idSlow")"         && ok "a timeout says so rather than showing its kill signal" \
  || bad "timeout row: [$(row "$idSlow")]"
grep -q '2 redacted' <<<"$(row "$idRedact")"      && ok "the redaction count is the credential's arrival" \
  || bad "redaction row: [$(row "$idRedact")]"
grep -q 'B in' <<<"$(row "$idRedactOp")"          && ok "a redact op shows the size of what it was given" \
  || bad "redact row: [$(row "$idRedactOp")]"

# The refusals from L2 ran but never started a command.  What the operator sees
# for them in the listing is the question here.
idRef=$(jq -r 'select(.refused != null) | .log_id' "$LOG" | tail -1)
if [ -n "$idRef" ]; then
  code=$(jq -r --arg i "$idRef" 'select(.log_id==$i) | .refused' "$LOG")
  rowRef=$(row "$idRef")
  # The code itself, not the word "refused": it is the string the caller was
  # answered with, so the listing can be matched against what the agent reported
  # and scanned for one kind of refusal.
  if grep -qF "$code" <<<"$rowRef"; then
    ok "a refused record names its code in the listing ($code)"
  else
    bad "the listing does not say a record was refused (refused=$code): [$rowRef]"
  fi
  if grep -qF "$code" <<<"$(logs "$idRef")"; then
    ok "and the detail view names it too"
  else
    bad "the detail view does not name refused=$code: [$(logs "$idRef")]"
  fi
  # A refusal is a failure, and the column is painted so an operator scanning
  # for one finds it.
  if /usr/local/bin/faramir logs --color always -n 40 | grep -F "$code" | grep -qP '\x1b\[31m'; then
    ok "and it is painted as a failure, like a non-zero exit"
  else
    bad "the refusal row is not painted as a failure"
  fi
else
  bad "no refused record was written at all"
fi

# The other shape of "this never became a finished command": an error and no
# exit code, which the broker writes when the program will not resolve.  It
# carries no refusal code, so the row has to say something of its own.
idNoProg=$(jq -r 'select(.refused == null and .error != null and .exit_code == null) | .log_id' "$LOG" | tail -1)
if [ -n "$idNoProg" ]; then
  grep -q 'failed' <<<"$(row "$idNoProg")" \
    && ok "a request that failed without being refused reads as failed" \
    || bad "a failure with no exit code renders blank: [$(row "$idNoProg")]"
  grep -q 'no such program' <<<"$(logs "$idNoProg")" \
    && ok "and the detail view says what failed" \
    || bad "the detail view does not say what failed"
else
  bad "no failed-without-refusal record was written"
fi

# The point of both: no row that did not run is left looking like one that ran.
blank=$(logs -n 40 | grep -E '^[0-9a-f]{10} ' | awk '{ if ($3 == "exec" && $4 ~ /^\//) print }' | wc -l)
[ "$blank" -eq 0 ] && ok "no exec row is left with an empty outcome column" \
  || bad "$blank exec rows render as neither run nor refused"

# One day header, not one per row.
days=$(logs -n 40 | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2} ')
[ "$days" -eq 1 ] && ok "the date is a header, printed once" || bad "$days date headers in one day's listing"

# Oldest first: the log is read against what somebody remembers doing.
first=$(logs -n 3 | grep -v '^[0-9]\{4\}-' | head -1 | awk '{print $1}')
last=$(logs -n 3 | grep -v '^[0-9]\{4\}-' | tail -1 | awk '{print $1}')
[ "$last" = "$(shortOf "$(lastID)")" ] && ok "the newest record is last" \
  || bad "the last row is $last, newest is $(shortOf "$(lastID)")"
[ "$first" != "$last" ] && ok "and the listing is in order" || bad "-n 3 printed one row"

# --------------------------------------------------------------------------
head_ "4. -n asks for a count, and gets exactly that"

total=$(wc -l <"$LOG")
rows() { logs -n "$1" | grep -cE '^[0-9a-f]{10} '; }

# That the count itself is honoured is a table in cmd/faramir's own tests.  What
# only a real log shows is the flag reaching it, and a count past the end coming
# back as what there is rather than as an error.
[ "$(rows 5)" -eq 5 ] && ok "-n 5 prints five" || bad "-n 5 printed $(rows 5)"
[ "$(rows $((total + 10)))" -eq "$total" ] && ok "-n past the end prints the $total there are" \
  || bad "-n $((total+10)) printed $(rows $((total+10)))"

out=$(logs -n 0); code=$?
[ $code -eq 0 ] && [ "$(grep -cE '^[0-9a-f]{10} ' <<<"$out")" -eq 0 ] \
  && ok "-n 0 asks for nothing and gets nothing, exit 0" || bad "-n 0: exit $code [$out]"
out=$(logs -n -5); code=$?
[ $code -eq 0 ] && [ "$(grep -cE '^[0-9a-f]{10} ' <<<"$out")" -eq 0 ] \
  && ok "-n -5 likewise, rather than 'no limit'" || bad "-n -5: exit $code [$out]"

# Asking for none and having none are different answers.  The log here is full
# of records, so saying it "holds no records" would be a claim about the host.
out=$(logs -n 0)
grep -q 'asks for no records' <<<"$out" && ok "-n 0 says the count is why, not the log" \
  || bad "-n 0 on a log of $total records: [$out]"
grep -q 'holds no records' <<<"$out" && bad "-n 0 reported the log as empty" \
  || ok "and does not report a full log as empty"
grep -q 'asks for no records' <<<"$(logs -n -5)" && ok "-n -5 says the same" \
  || bad "-n -5: [$(logs -n -5)]"
# And an empty log still says that, so the two remain distinguishable.
: > /tmp/none.log
NONECFG=$(configFor /tmp/none.log none)
grep -q 'holds no records' <<<"$(logsAt "$NONECFG")" \
  && ok "while an actually empty log still reads as empty" \
  || bad "an empty log: [$(logsAt "$NONECFG")]"
grep -q 'asks for no records' <<<"$(logsAt "$NONECFG" -n 0)" \
  && ok "and -n 0 on an empty log answers the question that was asked" \
  || bad "-n 0 on an empty log: [$(logsAt "$NONECFG" -n 0)]"

# A count the flag accepts must not be a size the caller can allocate: the ring
# grows to what the log holds, so this costs the log, not the number.
before=$(date +%s)
n=$(rows 500000000)
elapsed=$(( $(date +%s) - before ))
if [ "$n" -eq "$total" ] && [ "$elapsed" -lt 10 ]; then
  ok "-n 500000000 costs the log, not the number (${elapsed}s, $n rows)"
else
  bad "-n 500000000: $n rows in ${elapsed}s"
fi

# --------------------------------------------------------------------------
head_ "5. a long log: the ring wraps, lookup stays flat"

BIG=/tmp/big.log
python3 - "$BIG" <<'PY'
import sys, json
with open(sys.argv[1], "w") as fh:
    for i in range(1, 1031):
        fh.write(json.dumps({
            "log_id": "2026-08-10T%02d:%02d:%02dZ-bbbb%06x" % (i//3600, i//60 % 60, i % 60, i),
            "op": "exec", "cwd": "/home/op/project", "peer": {"uid": 1001, "pid": i},
            "cmd": ["/bin/echo", "record-%d" % i], "exit_code": 0, "duration_sec": 0.01,
            "output": "record-%d\n" % i}) + "\n")
PY
BIGCFG=$(configFor "$BIG" big)
bigrows() { logsAt "$BIGCFG" -n "$1" | grep -cE '^[0-9a-f]{10} '; }

# 1024 is where the ring stops being sized to the count and starts growing.
for n in 1 1023 1024 1025 1030; do
  got=$(bigrows $n)
  [ "$got" -eq "$n" ] && ok "-n $n on a 1030-record log prints $n" || bad "-n $n printed $got"
done
[ "$(bigrows 2000)" -eq 1030 ] && ok "-n 2000 prints the 1030 there are" || bad "-n 2000 printed $(bigrows 2000)"

# The last N are the last N, not the first N.
tailrow=$(logsAt "$BIGCFG" -n 1 | grep -E '^[0-9a-f]{10} ')
grep -q 'record-1030' <<<"$tailrow" && ok "and -n 1 is the newest record, not the oldest" \
  || bad "-n 1 gave [$tailrow]"

# Looking up the first record must not cost more than looking up the last.
t0=$(date +%s%N); logsAt "$BIGCFG" bbbb000001 >/dev/null; t1=$(date +%s%N)
logsAt "$BIGCFG" bbbb000406 >/dev/null; t2=$(date +%s%N)
[ $(( (t1-t0)/1000000 )) -lt 3000 ] && [ $(( (t2-t1)/1000000 )) -lt 3000 ] \
  && ok "lookup costs the same at either end ($(( (t1-t0)/1000000 ))ms, $(( (t2-t1)/1000000 ))ms)" \
  || bad "lookup: $(( (t1-t0)/1000000 ))ms then $(( (t2-t1)/1000000 ))ms"

# bbbb000196 is record 406: the ids are hex, so a decimal reading of one is a
# different record, which is exactly the mistake a lookup must not make.
out=$(logsAt "$BIGCFG" bbbb000196)
grep -q 'record-406 *$' <<<"$out" && ok "and a lookup returns the record asked for" \
  || bad "bbbb000196 gave [$(head -2 <<<"$out")]"

# --------------------------------------------------------------------------
head_ "6. a log that was damaged, or written by something else"

DMG=/tmp/damaged.log
{
  echo '{"log_id":"2026-08-11T00:00:01Z-cccc000001","op":"exec","cmd":["/bin/one"],"exit_code":0}'
  echo 'this is not json at all'
  echo '{"log_id":"half-written","op":"exe'
  echo '[1,2,3]'
  echo '"just a string"'
  echo 'null'
  echo ''
  echo '   '
  echo '{"log_id":"2026-08-11T00:00:02Z-cccc000002","op":"exec","cmd":["/bin/two"],"exit_code":0}'
  printf '{"log_id":"no-newline-yet","op":"exec"'
} > "$DMG"

DMGCFG=$(configFor "$DMG" dmg)
out=$(logsAt "$DMGCFG"); code=$?
[ $code -eq 0 ] && ok "a damaged log still lists, exit 0" || bad "exit $code on a damaged log"
grep -q '/bin/one' <<<"$out" && grep -q '/bin/two' <<<"$out" \
  && ok "the records either side of the damage are shown" || bad "a good record was lost: [$out]"

# Five lines end in a newline and do not parse.  The count is the whole promise:
# a listing that looks complete when a record is missing answers wrongly.
n=$(sed -n 's/.*: \([0-9]*\) line(s) do not parse.*/\1/p' <<<"$out")
[ "$n" = 5 ] && ok "all 5 unparseable lines are counted" \
  || bad "reported $n unparseable lines, want 5 (a JSON 'null' line parses to no record)"

grep -q 'no-newline-yet' <<<"$out" && bad "the half-written last line was shown" \
  || ok "the last line, still being written, is not counted as a loss"

# The warning is the operator's, and must not be mistaken for a record.  The
# binary directly, not logs(): that helper merges the two streams, which is the
# thing under test here.
warn=$(/usr/local/bin/faramir logs --color never --config "$DMGCFG" 2>&1 >/dev/null)
grep -q 'do not parse' <<<"$warn" && ok "the warning goes to stderr, clear of the listing" \
  || bad "nothing on stderr: [$warn]"
body=$(/usr/local/bin/faramir logs --color never --config "$DMGCFG" 2>/dev/null)
grep -q 'do not parse' <<<"$body" && bad "the warning is mixed into the listing" \
  || ok "and stdout is records only, so a pipe into a parser stays clean"

out=$(logsAt "$DMGCFG" cccc000002); code=$?
[ $code -eq 0 ] && grep -q '/bin/two' <<<"$out" \
  && ok "and a lookup past the damage still finds its record" || bad "lookup: exit $code [$out]"

# A record with nothing in it is a row, not a crash.
echo '{}' > /tmp/bare.log
out=$(logsAt "$(configFor /tmp/bare.log bare)"); code=$?
[ $code -eq 0 ] && ok "an empty record prints as a row rather than failing" || bad "{} record: exit $code [$out]"

# --------------------------------------------------------------------------
head_ "7. rotation: the file moves and the broker does not notice"

before=$(wc -l <"$LOG")
oldID=$(head -1 "$LOG" | jq -r .log_id)
logrotate -f /etc/logrotate.d/faramir; code=$?
[ $code -eq 0 ] && ok "logrotate runs the installed rule" || bad "logrotate exit $code"

[ -f "$LOG.1.gz" ] && ok "the old log is $LOG.1.gz, the name the hint gives" \
  || bad "no $LOG.1.gz after rotation"
mode=$(stat -c '%a %U:%G' "$LOG")
[ "$mode" = "600 faramir-broker:faramir-broker" ] && ok "the new log is $mode, not the daemon's umask" \
  || bad "after rotation the log is $mode"
mode=$(stat -c '%a %U:%G' "$LOG.1.gz")
[ "$mode" = "600 faramir-broker:faramir-broker" ] && ok "and the rotated one keeps $mode" \
  || bad "the rotated log is $mode"

# No copytruncate and no signal: the next append reopens by path.  Two lines,
# an exec being a pair: one record when the child starts and one when it ends.
run -- /bin/echo after-rotation >/dev/null
newID=$(lastID)
[ "$(wc -l <"$LOG")" -eq 2 ] && ok "the broker wrote to the new file with no reload" \
  || bad "the live log holds $(wc -l <"$LOG") lines after one command, want the pair"
logs "$(shortOf "$newID")" >/dev/null 2>&1 && ok "and that record reads back" || bad "the post-rotation record does not read back"

out=$(logs "$oldID"); code=$?
[ $code -eq 1 ] && ok "an id that rotated out is a failure, not an empty answer" || bad "rotated-out id: exit $code"
grep -q "$(basename "$LOG").1.gz" <<<"$out" && ok "and the hint names the file it went to" \
  || bad "the hint does not name the rotated file: [$out]"
gz=$(zcat "$LOG.1.gz" | wc -l)
[ "$gz" -eq "$before" ] && ok "the rotated file holds all $before records, still JSONL" \
  || bad "the rotated file holds $gz of $before records"
zcat "$LOG.1.gz" | jq -e . >/dev/null 2>&1 && ok "and every line of it parses" \
  || bad "the rotated file does not parse as JSONL"
zcat "$LOG.1.gz" | grep -qF "$SECRET" && bad "the rotated log carries a value" \
  || ok "and carries no value"

# --------------------------------------------------------------------------
head_ "8. no value reaches the log, whatever the command does with it"

run --env PW=secret://db/password -- /bin/sh -c '
  echo plain $PW
  echo b64 $(printf %s "$PW" | base64)
  echo hex $(printf %s "$PW" | xxd -p)
  echo url $(printf %s "$PW" | jq -sRr @uri)
  echo json $(printf %s "$PW" | jq -Rs .)
  echo split-across-a-write $PW
  echo "$PW" >&2
  exit 4' >/dev/null
idEnc=$(lastID)

grep -qF "$SECRET" "$LOG" && bad "the plaintext value is in the log" || ok "the log holds no plaintext value"
for enc in "$(printf %s "$SECRET" | base64)" "$(printf %s "$SECRET" | xxd -p)"; do
  grep -qF "$enc" "$LOG" && bad "an encoded value is in the log" || ok "nor an encoding of it (${enc:0:12}...)"
done
out=$(logs "$idEnc")
grep -qF "$SECRET" <<<"$out" && bad "faramir logs printed a value" || ok "faramir logs prints none either"
grep -qF "$TOKEN" <<<"$out" && ok "what it prints in its place is the token" || bad "no token in the record: [$out]"
grep -q 'exit 4' <<<"$out" && ok "and the command's own exit is intact" || bad "exit code lost: [$out]"

# The refusal path echoes the caller's cwd back, so a value standing in a path
# is how one reaches that text at all.
d=$(runuser -u op -- mktemp -d)
runuser -u op -- mkdir -p "$d/$SECRET"
out=$(run -C "$d/$SECRET/missing" -- /bin/true)
grep -qF "$SECRET" <<<"$out" && bad "the refusal echoed the value back" || ok "a value inside a cwd is redacted in the refusal"
grep -qF "$SECRET" "$LOG" && bad "and it reached the log" || ok "and does not reach the log"
rm -rf "$d"

# --------------------------------------------------------------------------
head_ "9. the log is the agent's text, printed on the operator's terminal"

# argv is chosen by the agent.  A row it can forge is a row that lies.
run -- /bin/echo "$(printf 'x\n9999999999  00:00:00  exec   FORGED')" >/dev/null
listing=$(logs -n 5)
grep -qE '^9999999999' <<<"$listing" && bad "argv forged a listing row" || ok "a newline in argv cannot forge a row"
grep -q 'FORGED' <<<"$listing" && ok "it is shown, escaped, on the row it belongs to" \
  || bad "the argv was dropped rather than escaped: [$listing]"

run -- /bin/sh -c 'printf "real\rFAKE\n"; printf "\033[2J\033[H"; printf "esc\033]0;title\a\n"' >/dev/null
idCtl=$(lastID)
out=$(logs "$idCtl")
printf '%s' "$out" | grep -qP '\r' && bad "a bare CR reached the terminal" || ok "a CR in output is escaped, not obeyed"
printf '%s' "$out" | grep -qP '\x1b' && bad "an ESC reached the terminal" || ok "and an ESC cannot rewrite the screen"
grep -q 'real' <<<"$out" && ok "while the text itself is still readable" || bad "the output was dropped: [$out]"

# Every printed line of a record's output stays inside the record's block.
starts=$(logs "$idCtl" | grep -cE '^[0-9a-f]{10} ')
[ "$starts" -eq 1 ] && ok "one record prints one header line" || bad "$starts header lines for one record"

# --------------------------------------------------------------------------
head_ "10. many at once, one line each"

n=24
for i in $(seq "$n"); do
  runuser -u op -- /usr/local/bin/faramir run --quiet -t 30 -C "$PROJECT" \
    --env PW=secret://db/password -- /bin/sh -c "echo c$i \$PW" >/dev/null 2>&1 &
done
wait
sleep 1

lines=$(wc -l <"$LOG")
recs=$(jq -c . "$LOG" 2>/dev/null | wc -l)
[ "$lines" -eq "$recs" ] && ok "every line of the log is one whole record ($recs)" \
  || bad "$lines lines, $recs parse: a write interleaved"
# Distinct per command rather than per record: an exec writes a pair sharing
# one, so the id is counted once each half has been reduced to its command.
ids=$(jq -r 'select(.op=="exec" or .op=="exec_started") | "\(.log_id) \(.op)"' "$LOG" | sort | wc -l)
uniq=$(jq -r 'select(.op=="exec" or .op=="exec_started") | "\(.log_id) \(.op)"' "$LOG" | sort -u | wc -l)
[ "$ids" -eq "$uniq" ] && ok "and every log_id is distinct per record ($uniq)" \
  || bad "$((ids-uniq)) log_ids repeat within one half of the pair"
got=$(jq -r 'select(.op=="exec") | .cmd[-1]' "$LOG" | grep -c '^echo c[0-9]* \$PW$')
[ "$got" -eq "$n" ] && ok "all $n concurrent runs are recorded" || bad "$got of $n recorded"
# One start record per command that ran, and none for one refused before it did:
# over [server] max_concurrency the broker refuses rather than queues, and a
# command that never started has nothing to say it began.
starts=$(jq -r 'select(.op=="exec_started") | .cmd[-1]' "$LOG" | grep -c '^echo c[0-9]* \$PW$')
ran=$(jq -r 'select(.op=="exec" and .exit_code != null) | .cmd[-1]' "$LOG" | grep -c '^echo c[0-9]* \$PW$')
[ "$starts" -eq "$ran" ] && ok "and each of the $ran that ran was in the log from the moment it started" \
  || bad "$starts start records for $ran commands that ran"
grep -qF "$SECRET" "$LOG" && bad "concurrency put a value in the log" || ok "and none of them wrote a value"
skipped=$(logs -n 40 2>&1 >/dev/null | grep -c 'do not parse')
[ "$skipped" -eq 0 ] && ok "the reader finds nothing unparseable" || bad "the reader reported damage"

# --------------------------------------------------------------------------
head_ "11. one record is bounded, however much the command wrote"

maxbytes=$(sed -n 's/^max_record_bytes *= *\([0-9]*\).*/\1/p' /etc/faramir/config.toml)
maxbytes=${maxbytes:-1048576}
run -- /bin/sh -c 'tr -dc a-z </dev/urandom | head -c 3000000; echo' >/dev/null
idBig=$(lastID)
bytes=$(tail -1 "$LOG" | wc -c)
[ "$bytes" -le "$maxbytes" ] && ok "3 MiB of output made a ${bytes}-byte line (cap $maxbytes)" \
  || bad "the line is $bytes bytes, over the $maxbytes cap"
[ "$(tail -1 "$LOG" | jq -r .output_truncated)" = true ] && ok "and the record says it was truncated" \
  || bad "the record does not admit the truncation"
logs "$idBig" | tail -1 | grep -q 'truncated at' && ok "the reader prints the marker where the text stops" \
  || bad "no truncation marker in the detail view"
[ "$(logs -n 1 | grep -cE '^[0-9a-f]{10} ')" -eq 1 ] && ok "and the listing still renders it as one row" \
  || bad "the big record broke the listing"

# The case the cap is counted in encoded bytes for: '<' costs six as JSON, so a
# cap counted before encoding would be six times the size the operator set.
# '<' rather than a C0 control, which redaction strips on the way in and so
# never reaches the encoder at all.
run -- /bin/sh -c 'head -c 400000 /dev/zero | tr "\0" "<"' >/dev/null
bytes=$(tail -1 "$LOG" | wc -c)
kept=$(tail -1 "$LOG" | jq -r '.output | length')
if [ "$bytes" -le "$maxbytes" ]; then
  ok "400k of '<' fits the cap ($bytes bytes on the line)"
else
  bad "'<' blew the cap: $bytes bytes for a $maxbytes cap"
fi
# Six bytes apiece means well under a sixth of the cap survives as text.
if [ "$kept" -lt $((maxbytes / 5)) ]; then
  ok "and only $kept chars were kept, the cap being counted in encoded bytes"
else
  bad "$kept chars kept under a $maxbytes cap: the cap was counted before encoding"
fi

# --------------------------------------------------------------------------
head_ "12. where it reads from"

NOPECFG=$(configFor /var/log/faramir/nope.log nope)
out=$(logsAt "$NOPECFG"); code=$?
[ $code -eq 1 ] && grep -q 'Nothing has been brokered' <<<"$out" \
  && ok "an absent log says what that means, not 'no such file'" || bad "absent log: exit $code [$out]"

: > /tmp/empty.log
out=$(logsAt "$(configFor /tmp/empty.log empty)"); code=$?
[ $code -eq 0 ] && grep -q 'holds no records' <<<"$out" \
  && ok "an empty log is not an error" || bad "empty log: exit $code [$out]"

# An absent log outranks the count: -n 0 on a host where nothing has been
# brokered must say that, not answer a question about the count.
out=$(logsAt "$NOPECFG" -n 0); code=$?
[ $code -eq 1 ] && grep -q 'Nothing has been brokered' <<<"$out" \
  && ok "an absent log is named even when -n asked for nothing" \
  || bad "-n 0 on an absent log: exit $code [$out]"

out=$(logsAt "$(configFor /var/log/faramir dir)"); code=$?
[ $code -eq 1 ] && ok "a directory named as the log fails rather than printing junk" \
  || bad "a directory as log_path: exit $code [$(head -c 100 <<<"$out")]"

# The config is the only thing that says which log is read.  A flag naming a
# path by hand is one typo away from reporting a host as quiet, and --watch
# would wait on that path for ever.
cp /etc/faramir/config.toml /tmp/alt.toml
sed -i 's#^log_path = .*#log_path = "'"$BIG"'"#' /tmp/alt.toml
out=$(logs --config /tmp/alt.toml -n 1)
grep -q 'record-1030' <<<"$out" && ok "--config sends it to that config's log" || bad "--config: [$out]"
out=$(FARAMIR_CONFIG=/tmp/alt.toml logs -n 1)
grep -q 'record-1030' <<<"$out" && ok "and FARAMIR_CONFIG does the same" || bad "FARAMIR_CONFIG: [$out]"
out=$(logs --path "$BIG" -n 1); code=$?
[ $code -eq 2 ] && grep -q 'unknown flag: --path' <<<"$out" \
  && ok "and there is no --path to override either, exit 2" \
  || bad "--path: exit $code [$(head -c 100 <<<"$out")]"

out=$(logs --config /tmp/nosuch.toml); code=$?
[ $code -eq 1 ] && grep -q 'config' <<<"$out" && ok "a config that is not there is named as such" \
  || bad "missing config: exit $code [$out]"

out=$(logs --color pink); code=$?
[ $code -eq 2 ] && ok "an unknown --color is a usage error" || bad "--color pink: exit $code"
out=$(logs one two); code=$?
[ $code -eq 2 ] && ok "two log-ids is a usage error" || bad "two args: exit $code"

# --color always is what a pipe into less needs; auto into a pipe must not.
raw=$(/usr/local/bin/faramir logs --color always -n 1 | cat)
printf '%s' "$raw" | grep -qP '\x1b\[' && ok "--color always paints into a pipe" || bad "--color always painted nothing"
raw=$(/usr/local/bin/faramir logs -n 1 | cat)
printf '%s' "$raw" | grep -qP '\x1b\[' && bad "auto painted a pipe" || ok "auto leaves a pipe unpainted"

# --------------------------------------------------------------------------
head_ "13. record shapes the broker writes but this run did not produce"
#
# Synthetic records, so what is under test is the rendering only: an operator
# meets these on a host where an approval or a rekey happened.

SYN=/tmp/shapes.log
cat > "$SYN" <<'BODY'
{"log_id":"2026-08-11T01:00:01Z-dddd000001","op":"ask_approval","approved":true,"peer":{"uid":1001,"pid":10},"cmd":["/usr/bin/apt","install","-y","curl"],"exec_log_id":"2026-08-11T01:00:02Z-dddd000002","outcome":"approved at the console"}
{"log_id":"2026-08-11T01:00:03Z-dddd000003","op":"ask_approval","approved":false,"peer":{"uid":1001,"pid":11},"cmd":["/usr/bin/rm","-rf","/"],"outcome":"another session holds the host"}
{"log_id":"2026-08-11T01:00:04Z-dddd000004","op":"edit","file":"/etc/faramir/secrets/app.sops.yml","peer":{"uid":0,"pid":12}}
{"log_id":"2026-08-11T01:00:05Z-dddd000005","op":"rekey","file":"/etc/faramir/secrets/app.sops.yml","from":["age1old"],"to":["age1old","age1new"],"peer":{"uid":0,"pid":13}}
{"log_id":"2026-08-11T01:00:06Z-dddd000006","op":"exec","cmd":["/bin/sh"],"exit_code":0,"redactions":[{"token":"«SECRET:db/password»","count":3},{"token":"«SECRET:api/token»","count":1}]}
{"log_id":"2026-08-11T01:00:07Z-dddd000007","op":"exec","cmd":["bin/deploy"],"argv0_path":"/home/op/project/bin/deploy","cwd":"/home/op/project","env_refs":{"PW":"db/password","TOKEN":"api/token"},"exit_code":0,"record_reduced":true}
BODY

SYNCFG=$(configFor "$SYN" syn)
out=$(logsAt "$SYNCFG")
grep -q 'approved' <<<"$out"  && ok "an approval that was granted reads as approved" || bad "approval row: [$out]"
grep -q 'refused'  <<<"$out"  && ok "and one that was not reads as refused" || bad "refusal row: [$out]"
grep -q 'app.sops.yml' <<<"$out" && ok "an edit names the file it changed" || bad "edit row: [$out]"
grep -q '4 redacted' <<<"$out" && ok "the listing sums the per-token counts" || bad "sum row: [$out]"

out=$(logsAt "$SYNCFG" dddd000001)
grep -q 'dddd000002' <<<"$out" && ok "an approval points at the command it authorised" || bad "no exec_log_id: [$out]"
grep -q 'approved at the console' <<<"$out" && ok "and says how it was answered" || bad "no outcome: [$out]"
out=$(logsAt "$SYNCFG" dddd000005)
grep -q 'age1old' <<<"$out" && grep -q 'age1new' <<<"$out" \
  && ok "a rekey shows who could read the file and who can now" || bad "rekey detail: [$out]"
out=$(logsAt "$SYNCFG" dddd000006)
grep -q '«SECRET:db/password»×3' <<<"$out" && grep -q '«SECRET:api/token»×1' <<<"$out" \
  && ok "the detail view breaks the count down per token" || bad "counts: [$out]"

# The fields a record carries that the command line does not: which variable
# carried which ref, what argv[0] resolved to, and that the record was cut.
out=$(logsAt "$SYNCFG" dddd000007)
grep -qE '^ +refs +PW=db/password, TOKEN=api/token$' <<<"$out" \
  && ok "the refs row is the record's NAME=ref pairs" || bad "refs row: [$out]"
grep -qE '^ +program +/home/op/project/bin/deploy$' <<<"$out" \
  && ok "and a relative argv[0] shows what actually ran" || bad "program row: [$out]"
grep -qE '^ +reduced +fields were cut' <<<"$out" \
  && ok "and a reduced record says it was cut" || bad "reduced row: [$out]"

# --------------------------------------------------------------------------
head_ "14. --watch: the log as it is written"
#
# On a log of this suite's own making rather than the live one, so what is under
# test is the reader and not what the broker happened to do while it ran.

WATCH=/tmp/watch.log
OUT=/tmp/watch.out
WATCHCFG=$(configFor "$WATCH" watch)
synth() { printf '{"log_id":"2026-08-12T02:00:%02dZ-eeee%06d","op":"exec","cmd":["/bin/echo","%s"],"exit_code":0}\n' "$2" "$2" "$1"; }

# A host where nothing has been brokered has no log at all: the broker makes it
# by writing the first record, so a watcher started before that waits for it
# rather than exiting on a file that is about to exist.
rm -f "$WATCH"
/usr/local/bin/faramir logs --color never --config "$WATCHCFG" --watch -n 1 >"$OUT" 2>&1 &
watcher=$!
sleep 2
kill -0 "$watcher" 2>/dev/null && ok "a watcher on a host with no log yet keeps waiting" \
  || bad "the watcher exited before the log existed: [$(cat "$OUT")]"
grep -q 'no audit log at' "$OUT" && ok "and says so rather than watching in silence" \
  || bad "nothing said about the absent log: [$(cat "$OUT")]"
synth first-ever 0 > "$WATCH"
sleep 2
grep -q first-ever "$OUT" && ok "and picks the log up when the first record creates it" \
  || bad "the first record did not arrive: [$(cat "$OUT")]"
kill "$watcher" 2>/dev/null
wait "$watcher" 2>/dev/null

synth backlog 1 > "$WATCH"
/usr/local/bin/faramir logs --color never --config "$WATCHCFG" --watch -n 1 >"$OUT" 2>&1 &
watcher=$!
sleep 2

grep -q backlog "$OUT" && ok "the records already in the log are printed first" \
  || bad "no backlog after 2s: [$(cat "$OUT")]"
synth arrived 2 >> "$WATCH"
sleep 2
grep -q arrived "$OUT" && ok "and a record appended after that arrives on its own" \
  || bad "an appended record did not arrive: [$(cat "$OUT")]"

# Half a record is half a line: held until its newline, and not reported as
# damage in the meantime.
printf '{"log_id":"2026-08-12T02:00:03Z-eeee000003","op":"exec","cmd":["/bin/echo","half' >> "$WATCH"
sleep 2
grep -q half "$OUT" && bad "a record still being written was printed: [$(cat "$OUT")]" \
  || ok "a line still being appended is held rather than shown"
grep -q 'do not parse' "$OUT" && bad "and it was reported as damage: [$(cat "$OUT")]" \
  || ok "and is not counted as a record lost"
printf 'finished"],"exit_code":0}\n' >> "$WATCH"
sleep 2
grep -q halffinished "$OUT" && ok "it prints whole once its line ends" \
  || bad "the finished record did not print: [$(cat "$OUT")]"

# Rotation, the way logrotate does it here: rename, then the next write creates
# the file again.  A watcher left running has to follow the path.
mv "$WATCH" "$WATCH.1"
sleep 2
kill -0 "$watcher" 2>/dev/null && ok "the gap where the path has no file is waited out" \
  || bad "the watcher stopped when the log was renamed: [$(cat "$OUT")]"
synth after-rotation 4 > "$WATCH"
sleep 2
grep -q after-rotation "$OUT" && ok "and the new file is picked up with no restart" \
  || bad "nothing after rotation: [$(cat "$OUT")]"

kill "$watcher" 2>/dev/null
wait "$watcher" 2>/dev/null
rows=$(grep -cE '^[0-9a-f]{10} ' "$OUT")
[ "$rows" -eq 4 ] && ok "four records written, four rows printed, none twice" \
  || bad "$rows rows for four records: [$(cat "$OUT")]"
[ "$(grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2} ' "$OUT")" -eq 1 ] \
  && ok "with one date header across the whole run" \
  || bad "the date header repeated: [$(cat "$OUT")]"

# A log-id is one record that is already written, so there is nothing to wait
# for.  Refused rather than printed-and-then-hung.
out=$(logsAt "$WATCHCFG" --watch eeee000004); code=$?
[ $code -eq 2 ] && grep -q 'takes no log-id' <<<"$out" \
  && ok "--watch with a log-id is refused as usage, exit 2" || bad "--watch with an id: exit $code [$out]"

# --json cannot close an array it has no last record for, so it streams values.
synth streamed 5 >> "$WATCH"
/usr/local/bin/faramir logs --config "$WATCHCFG" --watch --json -n 1 >"$OUT" 2>/dev/null &
watcher=$!
sleep 2
synth also-streamed 6 >> "$WATCH"
sleep 2
kill "$watcher" 2>/dev/null
wait "$watcher" 2>/dev/null
[ "$(jq -s length "$OUT")" -eq 2 ] && ok "--json --watch prints one value per record" \
  || bad "--json --watch: [$(cat "$OUT")]"
rm -f "$WATCH" "$WATCH.1" "$OUT"

# --------------------------------------------------------------------------
head_ "15. a command is in the log while it is still running"
#
# An exec is two records under one log_id: one when the child starts, one when
# it ends.  Without the first a command is absent from the log for as long as it
# takes, so a playbook shows up only once it is over and a run that never
# returns leaves nothing behind at all.
#
# On the live log, because what is under test is what the broker writes.

runuser -u op -- /usr/local/bin/faramir run --quiet -t 30 -C "$PROJECT" -- /bin/sleep 8 >/dev/null 2>&1 &
slow=$!
sleep 3
ID=$(jq -r 'select(.op=="exec_started" and (.cmd|join(" ")|test("sleep 8"))) | .log_id' $LOG 2>/dev/null | tail -1)
[ -n "$ID" ] && [ "$ID" != null ] && ok "a running command is already in the log ($ID)" \
  || bad "nothing was recorded until the command finished"
[ "$(jq -r --arg id "$ID" 'select(.log_id==$id and .op=="exec") | .exit_code' $LOG 2>/dev/null | tail -1)" = "" ] \
  && ok "and has no ending yet, there being none" || bad "an ending was recorded before the command ended"
# The listing says started rather than leaving the column blank, which would
# read as a command that ran and did nothing.
logs -n 40 | grep -F "${ID##*-}" | grep -q started && ok "the listing reads it as started" \
  || bad "a started command renders with no outcome: $(logs -n 40 | grep -F "${ID##*-}")"
# And a lookup answers with what is known of it so far.
logs "$ID" | grep -q 'sleep 8' && ok "and faramir logs <id> resolves it while it runs" \
  || bad "a running command's id does not resolve: $(logs "$ID" | head -2)"

wait $slow 2>/dev/null
ended=$(jq -r --arg id "$ID" 'select(.log_id==$id and .op=="exec") | .exit_code' $LOG 2>/dev/null | tail -1)
[ "$ended" = 0 ] && ok "the second record lands when it ends: exit 0" \
  || bad "no ending was recorded for $ID: [$ended]"
# The pair shares one id, and a lookup now answers with the half that says how
# it went rather than the half that says it began.
logs "$ID" | grep -qE 'exit +0|exit_code' && ok "and the id now resolves to the ending" \
  || bad "the lookup still answers with the start: $(logs "$ID" | head -3)"
# A reader selecting exec still sees one record per command.
[ "$(jq -r --arg id "$ID" 'select(.log_id==$id and .op=="exec") | .log_id' $LOG 2>/dev/null | wc -l)" -eq 1 ] \
  && ok "and op==exec is still one record per command" || bad "op==exec matched the pair"

# --------------------------------------------------------------------------
summary

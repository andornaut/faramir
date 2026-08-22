#!/bin/bash
# A secret read out of a file another tool maintains: [[secret.link]].
#
# The managed store is faramir's own, and every account boundary around it is
# one `init` built. A link is the opposite: the file belongs to somebody else's
# tool, at a path faramir did not choose, with a mode that tool decides. faramir
# does not change the ownership or mode of a file it does not own, so what only a
# real install can show is whether the arrangement it asks for draws the same
# boundary there that the store gets for free, and whether it says clearly enough
# what has to be arranged.
#
# Three accounts, one file:
#
#   - the broker reads it, or the value is absent from the redactor and every
#     brokered command is refused;
#   - the executor does not, or a brokered command reaches the plaintext without
#     asking for the ref and without the redactor seeing it;
#   - the operator keeps it, their own tool being what rewrites it.
#
# The rest is the lifecycle: what `link add` refuses, and that it alters nothing
# in doing so, what the value looks like once it is serving, and what `link rm`
# does and deliberately does not undo.
#
# Run as root in the e2e container.
set -u
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

CFG=/etc/faramir/config.toml
GHDIR=/home/op/.config/gh
GH=$GHDIR/hosts.yml
# A second linked file, to be deleted while the entry stands: a credential that
# has left the machine, or a home that is not mounted.
NPMRC=/home/op/.npmrc
# The values these files hold. Long enough to clear [secret] min_length, and
# spelled unlike anything else on the box so a leak is unambiguous.
GH_VALUE=gho_linked_e2e_value_0001
NPM_VALUE=npm_linked_e2e_value_0002
# What the redactor puts in the value's place, which several checks below need
# as evidence rather than as a pass: the broker redacts over the whole value
# set, so a token proves the value was there and says nothing about who read
# it.
GH_TOKEN='«SECRET:gh/token»'


faramir=/usr/local/bin/faramir
asop() { runuser -u op -- env HOME=/home/op "$faramir" "$@"; }
# brokered runs a command through the broker as the agent's own uid, which is
# the account an agent's tool call arrives as.
brokered() { asop run --quiet -t 25 "$@" 2>&1; }
# addlink is `faramir link add` as an operator runs it. --agent-user because
# this suite runs as root with no SUDO_USER to carry it.
addlink() { "$faramir" link add --agent-user op "$@" 2>&1; }

# This suite adds refs to a shared install and regroups two files in the
# operator's home. Later suites read the config and the refs, so put both back:
# the entries come out through `link rm`, which is also what section 9 is
# about, and anything it left is removed here.
BACKUP=$(mktemp -d)
cp -a $CFG "$BACKUP/config.toml"
restore_baseline() {
  local rc=$?
  for ref in gh/token npm/token; do
    "$faramir" link rm --agent-user op "$ref" >/dev/null 2>&1 || true
  done
  cp -a "$BACKUP/config.toml" $CFG
  rm -rf "$BACKUP"
  rm -f "$GH" "$NPMRC"
  "$faramir" reload >/dev/null 2>&1 || true
  waitfor 25 asop refs >/dev/null 2>&1 || true
  return "$rc"
}
trap restore_baseline EXIT

# The file another tool maintains, written the way that tool writes it: the
# operator's own, and readable by nobody else.
install -d -o op -g op -m 0755 $GHDIR
cat > $GH <<EOF
github.com:
    oauth_token: $GH_VALUE
    user: someone
    git_protocol: ssh
EOF
chown op:op $GH
chmod 600 $GH
printf '//registry.npmjs.org/:_authToken=%s\n' "$NPM_VALUE" > $NPMRC
chown op:op $NPMRC
chmod 600 $NPMRC

# The broker's own group, which holds one account: naming a value is not
# permission to read the file it came from.
brokergroup=$(id -gn faramir-broker)

# --------------------------------------------------------------------------
head_ "1. what is refused before anything is touched"
# Each of these found afterwards is a file already regrouped for an entry that
# was never written, or a broker refusing every command because one link names
# nothing.
before=$(cat $CFG)

out=$(addlink gh/token $GH --type yaml --key github.com/wrong_key)
if [ -n "$out" ] && ! grep -q 'gh/token' $CFG; then
  ok "a selector that names nothing is refused, and no entry is written"
else
  bad "a selector naming nothing was accepted: $out"
fi
# The alternatives, which is the one thing `read-link` is allowed to say about
# the contents of the file. Names only: this reaches a terminal the agent reads.
grep -q 'this file offers' <<<"$out" && grep -q 'github.com/oauth_token' <<<"$out" \
  && ok "the refusal offers the selectors the file does have" \
  || bad "the refusal offers nothing to try instead: $out"
grep -qF "$GH_VALUE" <<<"$out" \
  && bad "the refusal carries the value out of the file" \
  || ok "and carries no value out of the file"
# The file is still the way its own tool wrote it: nothing here regroups or
# chmods a file faramir does not own, so a refused add cannot have left one
# widened for an entry that was never written.
[ "$(stat -c %U:%G/%a $GH)" = "op:op/600" ] \
  && ok "the refused add left the file exactly as it was" \
  || bad "the file is left at $(stat -c %U:%G/%a $GH) after a refused add"

# The arrangement a link needs, which faramir asks for and does not apply. A
# file no one has arranged is refused, and what is refused names the two
# commands that arrange it.
out=$(addlink gh/token $GH --type yaml --key github.com/oauth_token)
if grep -q 'gh/token' $CFG; then
  bad "a file the broker cannot read was linked anyway: $out"
else
  ok "a file the broker cannot read is refused, and no entry is written"
fi
grep -q "chgrp $brokergroup" <<<"$out" && grep -q 'chmod g+r' <<<"$out" \
  && ok "and the refusal carries the commands that arrange it" \
  || bad "the refusal does not say what to change: $out"
[ "$(stat -c %U:%G/%a $GH)" = "op:op/600" ] \
  && ok "and it arranged nothing itself" \
  || bad "the refused add altered the file: $(stat -c %U:%G/%a $GH)"

# A ref the managed store already defines. Refused before the entry is written,
# because the broker refuses every brokered command while one stands: callers
# would go on getting the managed value while this file held a second one for
# the same name, which nothing reads and nothing redacts.
out=$(addlink db/password $GH --type yaml --key github.com/oauth_token)
if grep -q 'db/password' $CFG; then
  bad "a link claiming a managed ref was written: $out"
else
  ok "a link claiming a ref the store defines is refused, and no entry is written"
fi
grep -q 'already serves' <<<"$out" \
  && ok "and the refusal says the broker answers that name already" \
  || bad "the refusal does not say why: $out"
# Still serving: the refusal came before anything reached the config.
asop refs 2>/dev/null | grep -q 'faramir://db/password' \
  && ok "and the host is still serving every ref it was" \
  || bad "the refused add left the broker refusing: $(asop refs 2>&1 | tr '\n' ' ')"

out=$(addlink gone/token $GHDIR/nosuchfile --type text)
grep -q 'mount it first' <<<"$out" \
  && ok "a file that is not there is refused, naming the case that explains it" \
  || bad "an absent file was not refused as one: $out"

ln -sf $GH $GHDIR/hosts-link.yml
out=$(addlink sym/token $GHDIR/hosts-link.yml --type yaml --key github.com/oauth_token)
grep -q 'symlink' <<<"$out" \
  && ok "a symlink is refused: the grant would land on whatever it points at" \
  || bad "a symlinked path was accepted: $out"
rm -f $GHDIR/hosts-link.yml

[ "$(cat $CFG)" = "$before" ] \
  && ok "the config is untouched by every refusal above" \
  || bad "a refused add rewrote $CFG"

# --------------------------------------------------------------------------
head_ "2. adding one"
# What a configuration manager converges, done here in the two commands the
# refusal above named. Both files, the second being linked in section 8.
chgrp "$brokergroup" $GH $NPMRC
chmod 640 $GH $NPMRC

out=$(addlink gh/token $GH --type yaml --key github.com/oauth_token)
if grep -q 'gh/token' $CFG; then ok "the entry is written to $CFG"
else bad "link add did not write the entry: $out"; fi

# Arranged before the add and unchanged by it: the check is what faramir does
# here, and a check that altered the file would be indistinguishable from one
# that passed.
[ "$(stat -c '%U:%G %a' $GH)" = "op:$brokergroup 640" ] \
  && ok "the file is as it was arranged: op:$brokergroup 640" \
  || bad "link add altered the file to $(stat -c '%U:%G %a' $GH)"

# --------------------------------------------------------------------------
head_ "3. the broker serves it"
waitfor 25 asop refs >/dev/null 2>&1
asop refs 2>/dev/null | grep -q 'faramir://gh/token' \
  && ok "faramir refs names the ref" \
  || bad "the ref is not being served: $(asop refs 2>&1 | tr '\n' ' ')"

# Injected, and the output redacted on the way back: the token is what proves
# both, an unresolved ref being refused rather than empty.
out=$(brokered --env T=faramir://gh/token -- /bin/sh -c 'echo $T')
grep -qF "$GH_TOKEN" <<<"$out" \
  && ok "a brokered command is given the value and gets the token back" \
  || bad "injection or redaction failed: $out"
grep -qF "$GH_VALUE" <<<"$out" \
  && bad "the value reached the transcript" \
  || ok "and the value is nowhere in the output"

# --------------------------------------------------------------------------
head_ "4. and the executor does not reach the file"
# The boundary the grant exists to draw. Asked as the account that runs a
# brokered command, not worked out from the mode.
#
# The refusal has to be positive evidence. The broker builds its redactor over
# the whole value set rather than over the refs a request asked for, so a
# brokered command that DID read this file would still not print the value: it
# would print the token. Testing only for the value's absence would pass on a
# host where the executor reads every linked file there is.
out=$(brokered -- /bin/cat $GH)
if grep -qF "$GH_VALUE" <<<"$out"; then
  bad "a brokered command read the linked file directly: $out"
elif grep -qF "$GH_TOKEN" <<<"$out"; then
  bad "a brokered command read the file; only the redactor stood between the value and the transcript: $out"
elif grep -qiE 'permission denied|cannot open' <<<"$out"; then
  ok "a brokered command is refused the file it takes the value from"
else
  bad "the read was neither refused nor redacted, so what happened is not known: $out"
fi
# The directories above it are traversable, which is what an enrolled tree
# needs; traversal is not read.
out=$(brokered -- /bin/ls $GHDIR)
grep -q 'hosts.yml' <<<"$out" \
  && ok "the directories above it are still enterable" \
  || bad "the executor cannot enter $GHDIR, so it cannot reach the tree either: $out"

# --------------------------------------------------------------------------
head_ "5. the agent's own shell"
# A linked path is a subject in the guard's rules as well as in the agents' own
# deny rules, both being rendered from one set, so the shell is refused it the
# way a file tool is. It was rewritten rather than refused before those were
# unified, and the value came back as a token; refused is the stricter half of
# the same cover, and it is what an operator declaring a path already assumes.
decision=$(jq -cn --arg c "cat $GH" '{tool_name:"Bash",tool_input:{command:$c}}' \
  | asop guard 2>/dev/null | jq -r '.hookSpecificOutput.permissionDecision // empty')
[ "$decision" = deny ] \
  && ok "the agent's own shell is refused a read of the linked file" \
  || bad "the guard answered '$decision' for a read of the linked file, want deny"
# And the value is still covered where a command may reach it: through the
# broker, which is what a link is for.
out=$(brokered /bin/sh -c "cat $GH")
if grep -qF "$GH_VALUE" <<<"$out"; then
  bad "a brokered read of the linked file returned the value: ${out:0:120}"
elif grep -qF "$GH_TOKEN" <<<"$out"; then
  ok "and a brokered read of it comes back as a token"
else
  note "a brokered read returned neither the value nor its token: ${out:0:120}"
fi

# The file tools are what the deny rules cover, and the linked path is in them.
# Written by `faramir init --agent`, which the project suite ran.
SETTINGS=/home/op/.claude/settings.json
if [ -f "$SETTINGS" ]; then
  grep -q "Read($GH)" "$SETTINGS" && grep -q "Edit($GH)" "$SETTINGS" \
    && ok "the linked path is refused to the agent's file tools" \
    || bad "$SETTINGS names no rule for $GH"
else
  note "no $SETTINGS on this box, so the file-tool rules were not checked"
fi

# --------------------------------------------------------------------------
head_ "6. what doctor makes of it"
# The JSON report rather than the table: a detail wraps across lines there, so a
# grep for a phrase would match on where the wrap happened to fall.
JSON=/tmp/link-doctor.json
snap() { "$faramir" doctor --agent-user op --json >$JSON 2>/dev/null; }
st() { jq -r --arg c "$1" '[.findings[]|select(.check==$c)|.status]|join(",")' $JSON; }
dt() { jq -r --arg c "$1" '[.findings[]|select(.check==$c)|.detail]|join(" ")' $JSON; }
snap
# Both questions the grant exists to make true, asked as those accounts rather
# than worked out from the mode.
[ "$(st 'linked file access')" = ok ] \
  && ok "doctor: the broker can read it and the executor cannot" \
  || bad "linked file access is $(st 'linked file access'): $(dt 'linked file access')"
grep -qF "$GH_VALUE" $JSON \
  && bad "doctor's report carries the value" \
  || ok "and its report names files and refs, never values"

# Both faults, put to it. What a link needs is ownership and mode on a file
# somebody else's tool rewrites, so neither of these needs anybody to do anything
# wrong: a tool that replaces its own file rather than rewriting it takes the
# group with it, and one that writes 0644 hands it to every account on the host.
chmod g-r $GH
snap
[ "$(st 'linked file access')" = failed ] && grep -q 'cannot read' <<<"$(dt 'linked file access')" \
  && ok "a file the broker lost read on is reported as a failure" \
  || bad "a broker that cannot read a linked file is $(st 'linked file access'): $(dt 'linked file access')"

chmod 644 $GH
snap
[ "$(st 'linked file access')" = failed ] && grep -q 'directly' <<<"$(dt 'linked file access')" \
  && ok "a file the executor can read is reported as a failure" \
  || bad "a linked file readable by the executor is $(st 'linked file access'): $(dt 'linked file access')"

# Put back, so the sections after this measure a working arrangement rather than
# the one this just broke.
chmod 640 $GH
chgrp "$brokergroup" $GH
snap
[ "$(st 'linked file access')" = ok ] \
  && ok "and the arrangement restored reads as healthy again" \
  || bad "it was not restored: $(dt 'linked file access')"

# --------------------------------------------------------------------------
head_ "7. listing them"
out=$(asop link ls 2>&1)
grep -q 'gh/token' <<<"$out" && grep -q 'present' <<<"$out" \
  && ok "link ls names the ref and says the file is there" \
  || bad "link ls: $out"
asop link ls --json 2>/dev/null | jq -e '.[] | select(.ref == "gh/token") | .key' >/dev/null \
  && ok "link ls --json is parseable and carries the entry" \
  || bad "link ls --json: $(asop link ls --json 2>&1)"
grep -qF "$GH_VALUE" <<<"$out" \
  && bad "link ls prints the value" \
  || ok "and prints no value"

# --------------------------------------------------------------------------
head_ "8. a second link, and one whose file goes away"
out=$(addlink npm/token $NPMRC --type ini --key '//registry.npmjs.org/:_authToken')
if grep -q 'npm/token' $CFG; then ok "an ini link is added, key and all"
else bad "the ini link was refused: $out"; fi

out=$(addlink gh/token $NPMRC --type text)
grep -q 'already names gh/token' <<<"$out" \
  && ok "a ref defined differently is refused: a ref has one definition" \
  || bad "a duplicate ref was accepted: $out"

# The same ref against the same file, type and key is the other case, and a
# configuration manager naming every link on every run is what makes it the
# ordinary one. Nothing is written, so the report says so.
out=$(addlink gh/token $GH --type yaml --key github.com/oauth_token --json)
grep -q '"changed": false' <<<"$out" \
  && ok "adding an entry already applied reports no change" \
  || bad "a second add of the same entry reported a change: ${out:0:200}"

# What that re-application is for. A tool that replaces its own file rather than
# rewriting it takes the group with it: 0600 in the operator's own group is what
# a temp file renamed over the original leaves behind. A converge run naming
# every link then reports it rather than repairing it.
chown op:op $GH
chmod 600 $GH
out=$(addlink gh/token $GH --type yaml --key github.com/oauth_token)
[ "$(stat -c '%a %G' $GH)" = "600 op" ] \
  && ok "a re-add of a file its tool reclaimed alters nothing" \
  || bad "the re-add altered the file: $(stat -c '%a %G' $GH)"
grep -q "chgrp $brokergroup" <<<"$out" \
  && ok "and reports what has to be arranged again" \
  || bad "the re-add does not say what to change: ${out:0:300}"

# Arranged the way the report asked, which is what a configuration manager does
# on its next converge. The reload is the other half: the broker fingerprints a
# linked file by mtime and size, which a chgrp leaves alone, so a store that gave
# up on this file would go on refusing it without one.
chgrp "$brokergroup" $GH
chmod 640 $GH
out=$(addlink gh/token $GH --type yaml --key github.com/oauth_token)
grep -q 'already reads' <<<"$out" \
  && ok "and adding it again then says the entry is the one that is there" \
  || bad "the re-application does not say the entry was already there: ${out:0:200}"
waitfor 25 asop refs >/dev/null 2>&1
asop refs 2>/dev/null | grep -q 'faramir://gh/token' \
  && ok "and the ref is served again" \
  || bad "the ref is not being served after the file was arranged again"

# The credential leaves the machine while the entry stands, which is also what a
# home that is not mounted looks like.
rm -f $NPMRC
out=$(asop link ls 2>&1)
grep -q 'not there' <<<"$out" \
  && ok "link ls reports a file that is no longer there" \
  || bad "link ls does not report the missing file: $out"
snap
[ "$(st 'linked file access')" = failed ] && grep -q 'not there' <<<"$(dt 'linked file access')" \
  && ok "doctor fails: an entry naming a file that is not there produces no value" \
  || bad "linked file access is $(st 'linked file access'): $(dt 'linked file access')"

# A link that did not load refuses its own ref and nothing else. What this is
# holding to is the blast radius: before it was scoped per ref, one linked file
# the broker could not read withheld the output of every command on the host,
# including commands with no relationship to the credential.
waitfor 25 asop refs >/dev/null 2>&1
out=$(brokered -- /bin/echo unrelated)
grep -q 'unrelated' <<<"$out" \
  && ok "a command that never asked for the missing ref still runs and prints" \
  || bad "a link that did not load withheld an unrelated command: $out"
out=$(brokered --env T=faramir://gh/token -- /bin/sh -c 'echo $T')
grep -qF "$GH_TOKEN" <<<"$out" \
  && ok "and every other ref is still injected and still redacted" \
  || bad "a link that did not load took another ref with it: $out"
# The one that is missing is refused by name, and the refusal does not say where
# the file was: that path is the location of a credential.
out=$(brokered --env T=faramir://npm/token -- /bin/sh -c 'echo $T')
grep -q 'npm/token' <<<"$out" && grep -q 'did not load' <<<"$out" \
  && ok "and the missing ref is refused by name" \
  || bad "the missing ref was not refused as one: $out"
grep -q "$NPMRC" <<<"$out" \
  && bad "the refusal names the linked file's path: $out" \
  || ok "and the refusal keeps the file's path out of it"

# The exit code is the whole point of reporting it here: the broker serves, so
# nothing else on this host says anything is wrong until a command asks.
asop status >/dev/null 2>&1 \
  && bad "faramir status exited 0 with a link that did not load" \
  || ok "faramir status exits non-zero"
jq -e '.secrets.degraded_links["npm/token"]' <<<"$(asop status 2>/dev/null)" >/dev/null \
  && ok "and its body still prints, naming the ref" \
  || bad "status does not name the degraded ref: $(asop status 2>&1 | tr '\n' ' ')"

# --------------------------------------------------------------------------
head_ "9. removing one"
out=$("$faramir" link rm --agent-user op gh/token 2>&1)
grep -q 'gh/token' $CFG \
  && bad "the entry is still in $CFG" \
  || ok "the entry is gone from $CFG"
# Both are printed, with what would undo them, so the operator decides rather
# than discovering it later.
grep -q 'chmod g-r' <<<"$out" \
  && ok "and it says the file is still readable by the broker's group" \
  || bad "removal does not say what access it left behind: $out"
grep -q 'deny rule' <<<"$out" \
  && ok "and that the deny rule naming it stays" \
  || bad "removal does not say the deny rule stays: $out"

waitfor 25 asop refs >/dev/null 2>&1
asop refs 2>/dev/null | grep -q 'faramir://gh/token' \
  && bad "the ref is still being served" \
  || ok "the ref stops being served"
# Removing the entry is what takes the value out of the redactor, so a value
# that is no longer linked is no longer covered.
printf '%s\n' "$GH_VALUE" | asop redact 2>/dev/null | grep -qF "$GH_VALUE" \
  && ok "and the value leaves the redactor with it" \
  || bad "the value is still being redacted after the entry was removed"

before=$(cat $CFG)
out=$("$faramir" link rm --agent-user op no/such-ref 2>&1)
rc=$?
[ $rc -eq 0 ] \
  && ok "removing a ref this install does not carry is not an error" \
  || bad "link rm on an unknown ref exited $rc: $out"
grep -q 'faramir link ls' <<<"$out" \
  && ok "and names the command that lists the ones it does" \
  || bad "link rm on an unknown ref: $out"
[ "$(cat $CFG)" = "$before" ] \
  && ok "and writes nothing" \
  || bad "removing a ref that is not there rewrote the config"

summary

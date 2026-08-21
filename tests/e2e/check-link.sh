#!/bin/bash
# A secret read out of a file another tool maintains: [[secret.link]].
#
# The managed store is faramir's own, and every account boundary around it is
# one `init` built. A link is the opposite: the file belongs to somebody else's
# tool, at a path faramir did not choose, with a mode that tool decides. So what
# only a real install can show is whether the grant draws the same boundary
# there that the store gets for free.
#
# Three accounts, one file:
#
#   - the broker reads it, or the value is absent from the redactor and every
#     brokered command is refused;
#   - the executor does not, or a brokered command reaches the plaintext without
#     asking for the ref and without the redactor seeing it;
#   - the operator keeps it, their own tool being what rewrites it.
#
# The rest is the lifecycle: what `link add` refuses before it has touched
# anything, what the value looks like once it is serving, and what `link rm`
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
UID_OP=$(id -u op)
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
# The grant is made to run the probe and put back when it fails: a file the
# broker can read but is not told about is a widening with nothing to show for
# it.
[ "$(stat -c %U:%G/%a $GH)" = "op:op/600" ] \
  && ok "the access granted for the probe was put back" \
  || bad "the file is left at $(stat -c %U:%G/%a $GH) after a refused add"

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
out=$(addlink gh/token $GH --type yaml --key github.com/oauth_token)
if grep -q 'gh/token' $CFG; then ok "the entry is written to $CFG"
else bad "link add did not write the entry: $out"; fi

# The broker's own group, which holds one account: naming a value is not
# permission to read the file it came from.
brokergroup=$(id -gn faramir-broker)
[ "$(stat -c %G $GH)" = "$brokergroup" ] \
  && ok "the file is in $brokergroup" \
  || bad "the file is in $(stat -c %G $GH), want $brokergroup"
# Group read added, the owner's own bits as they were, and nothing for anybody
# else.
[ "$(stat -c %a $GH)" = "640" ] \
  && ok "mode 640: group read added and nothing widened for other" \
  || bad "mode is $(stat -c %a $GH), want 640"
[ "$(stat -c %U $GH)" = "op" ] \
  && ok "the owner is left alone, their tool being what rewrites the file" \
  || bad "the owner is now $(stat -c %U $GH)"

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
# The bash path is not refused by name: a linked file is at a path faramir did
# not choose, and the deny list only covers what somebody thought to name. What
# covers it is the rewrite, so reading the file as the agent still yields the
# token.
rewrite=$(jq -cn --arg c "cat $GH" '{tool_name:"Bash",tool_input:{command:$c}}' \
  | asop guard 2>/dev/null | jq -r '.hookSpecificOutput.updatedInput.command // empty')
if [ -n "$rewrite" ]; then
  # && rather than ;: a cd that failed would run the rewrite from runuser's own
  # working directory, which is outside the tree the enrolment configured, and
  # the check would be measuring a shell standing somewhere else.
  out=$(runuser -u op -- env HOME=/home/op XDG_RUNTIME_DIR="/run/user/$UID_OP" \
    bash -c "cd /home/op/project && $rewrite" 2>&1)
  # The token, not merely the absence of the value: a rewrite that failed for
  # any reason of its own prints neither, and reads as a wrapper doing its job.
  if grep -qF "$GH_VALUE" <<<"$out"; then
    bad "the agent's own shell read the value out of the linked file: $out"
  elif grep -qF "$GH_TOKEN" <<<"$out"; then
    ok "read through the wrapper, the value comes back as a token"
  else
    bad "the wrapper returned neither the value nor its token, so it is not what redacted this: $out"
  fi
else
  bad "the guard returned no rewrite for a read of the linked file"
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

# Both faults, put to it. The grant is modes and ownership on a file somebody
# else's tool rewrites, so neither of these needs anybody to do anything wrong:
# a tool that replaces its own file rather than rewriting it takes the group
# with it, and one that writes 0644 hands it to every account on the host.
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

# Put back, so the sections after this measure a working grant rather than the
# one this just broke.
chmod 640 $GH
chgrp "$brokergroup" $GH
snap
[ "$(st 'linked file access')" = ok ] \
  && ok "and the grant restored reads as healthy again" \
  || bad "the grant was not restored: $(dt 'linked file access')"

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
# rewriting it takes the grant with it: 0600 in the operator's own group is what
# a temp file renamed over the original leaves behind.
chown op:op $GH
chmod 600 $GH
out=$(addlink gh/token $GH --type yaml --key github.com/oauth_token)
[ "$(stat -c '%a %G' $GH)" = "640 $brokergroup" ] \
  && ok "and adding it again puts back a grant the owning tool took away" \
  || bad "the grant was not restored: $(stat -c '%a %G' $GH)"
grep -q 'already reads' <<<"$out" \
  && ok "saying it added nothing, the entry being the one that is there" \
  || bad "the re-application does not say the entry was already there: ${out:0:200}"
# The reload is the other half: the broker fingerprints a linked file by mtime
# and size, which a chgrp leaves alone, so a store that refused over this file
# would go on refusing without one.
waitfor 25 asop refs >/dev/null 2>&1
asop refs 2>/dev/null | grep -q 'faramir://gh/token' \
  && ok "and the ref is served again" \
  || bad "the ref is not being served after the grant was restored"

# The credential leaves the machine while the entry stands, which is also what a
# home that is not mounted looks like.
rm -f $NPMRC
out=$(asop link ls 2>&1)
grep -q 'not there' <<<"$out" \
  && ok "link ls reports a file that is no longer there" \
  || bad "link ls does not report the missing file: $out"
snap
[ "$(st 'linked file access')" = warn ] && grep -q 'not there' <<<"$(dt 'linked file access')" \
  && ok "doctor warns rather than failing: a credential removed is not a fault" \
  || bad "linked file access is $(st 'linked file access'): $(dt 'linked file access')"

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

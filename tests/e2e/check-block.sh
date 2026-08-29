#!/bin/bash
# A path the agent's file tools are blocked from and faramir never reads:
# [[secret.block]].
#
# The weaker of the two entries a file can get, and the one thing only a real
# install can show is exactly where that weakness sits. A link draws more
# boundaries than this does, and a suite that checked only the deny rule would
# report the two as the same feature.
#
# So the deny rule is asserted, then the broker's own refusal of the same entry,
# and then the two things a block deliberately still does not do: the file's
# mode is left alone, and the value is absent from the redactor. Both are the
# documented trade rather than gaps, and a change that quietly closed one would
# be a change that started reading the file.
#
# Run as root in the e2e container.
set -u
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

CFG=/etc/faramir/config.toml
# The file, at a path faramir did not choose, with a mode its owner decides.
KEYDIR=/home/op/.luks
KEY=$KEYDIR/luks.key
KEY_VALUE=luks_refused_e2e_value_0001
# A path that is not there: a key on a volume nobody has mounted.
ABSENT=/mnt/not-mounted/luks.key
# A directory, to check that naming one refuses what is under it.
SSHDIR=/home/op/.refused-ids
# A declared file a brokered command can still change, for the half of the trade
# a block leaves alone. Under the enrolled tree and owned by the executor: /home
# is the only tree it may write, and chmod needs ownership.
MANAGED=/home/op/project/refused-managed.key
# The account-wide rule file, and whether this suite is what created the marker
# that makes `--agent auto` write one. Declared before the trap that reads it.
CLAUDE_HOME=/home/op/.claude
RULES=/home/op/.claude/settings.json
MADE_CLAUDE_HOME=

faramir=/usr/local/bin/faramir
asop() { runuser -u op -- env HOME=/home/op "$faramir" "$@"; }
brokered() { asop run --quiet -t 25 "$@" 2>&1; }
# `faramir block` as an operator runs it. No --agent-user: no command but `init`
# takes one, and these read the operator [server] agent_user records, which the
# install this suite runs against has.
block() { "$faramir" block "$@" 2>&1; }

# This suite writes entries into a shared install and renders them into the
# operator's rule files. Later suites read both, so put the config back and take
# the entries out again.
BACKUP=$(mktemp -d)
cp -a $CFG "$BACKUP/config.toml"
restore_baseline() {
  local rc=$?
  for path in "$KEY" "$ABSENT" "$SSHDIR" "$MANAGED"; do
    "$faramir" block rm --path "$path" >/dev/null 2>&1 || true
  done
  cp -a "$BACKUP/config.toml" $CFG
  # Section 9 empties the rule file to check that a re-add restores it.
  [ -f "$BACKUP/settings.json" ] && cp -a "$BACKUP/settings.json" $RULES
  rm -rf "$BACKUP" "$KEYDIR" "$SSHDIR"
  rm -f /etc/refused-world.key "$MANAGED"
  rm -rf /etc/refused-strict
  "$faramir" block rm --path /etc/refused-strict >/dev/null 2>&1 || true
  "$faramir" link rm gh/refuse-suite >/dev/null 2>&1 || true
  "$faramir" block rm --path /etc/beside-a-link.key >/dev/null 2>&1 || true
  rm -rf /home/op/.config/gh
  [ -n "$MADE_CLAUDE_HOME" ] && rm -rf "$CLAUDE_HOME"
  "$faramir" reload >/dev/null 2>&1 || true
  waitfor 25 asop refs >/dev/null 2>&1 || true
  return "$rc"
}
trap restore_baseline EXIT

# The account-wide rule files are what a [[secret.block]] entry renders into,
# and `--agent auto` writes them only for an agent the home already carries. The
# container's home has none: the project suite enrols a tree, which is a
# different set of files. So the marker is created here, and removed on the way
# out, or every assertion below would degrade to "no rule file to check" and the
# suite would pass while testing nothing.
if [ ! -d $CLAUDE_HOME ]; then
  install -d -o op -g op -m 0700 $CLAUDE_HOME
  MADE_CLAUDE_HOME=yes
fi

install -d -o op -g op -m 0700 $KEYDIR
printf '%s\n' "$KEY_VALUE" > $KEY
chown op:op $KEY
chmod 600 $KEY
install -d -o op -g op -m 0700 $SSHDIR
printf 'a-key-nobody-should-read\n' > $SSHDIR/id_test
chown op:op $SSHDIR/id_test
chmod 600 $SSHDIR/id_test

# --------------------------------------------------------------------------
head_ "1. what is refused before anything is written"
# There is no grant and no probe here, so these are the only ways `block add`
# declines. Each is checked against the config as well as the exit status: a
# refusal that had already rewritten the file would be worse than no refusal.
before=$(cat $CFG)
# The tilde is meant to stay a tilde: what is being checked is that faramir
# refuses one rather than expanding it, so shellcheck's advice is the bug here.
# shellcheck disable=SC2088
for case in \
  "etc/luks.key|is relative" \
  "~/.ssh/id_ed25519|starts with ~" \
  "/etc/./luks.key|shortest form" \
  "/|every file on the host"; do
  path=${case%%|*}
  want=${case##*|}
  out=$(block add --path "$path" 2>&1)
  if grep -qF "$want" <<<"$out"; then
    ok "refused $path: names '$want'"
  else
    bad "adding $path did not name '$want': ${out:0:140}"
  fi
done
[ "$(cat $CFG)" = "$before" ] \
  && ok "and the config is byte-identical after every one of them" \
  || bad "a refused add rewrote the config"

# --------------------------------------------------------------------------
head_ "2. the entry, and the rule it exists for"
out=$(block add --path "$KEY")
grep -q "blocked $KEY" <<<"$out" \
  && ok "block add reports what it blocked" \
  || bad "block add: ${out:0:160}"

grep -q "$KEY" $CFG \
  && ok "the entry is in config.toml" \
  || bad "config.toml carries no entry for $KEY"
# The rule is the whole of what the entry does, so this is the assertion the
# feature stands on.
if [ -f $RULES ]; then
  grep -qF "Read($KEY)" $RULES \
    && ok "the agent's deny rules refuse reading it" \
    || bad "no Read rule for $KEY in $RULES"
  grep -qF "Edit($KEY)" $RULES \
    && ok "and writing it: a file the agent cannot read it can still destroy" \
    || bad "no Edit rule for $KEY in $RULES"
else
  bad "no rule file at $RULES, so the rule could not be checked"
fi

# --------------------------------------------------------------------------
head_ "3. what it deliberately does not do"
# The documented trade, asserted rather than assumed. A change that closed
# either of these would be a change that started reading the file, which is the
# thing this entry exists to avoid.
mode=$(stat -c '%a %U:%G' $KEY)
[ "$mode" = "600 op:op" ] \
  && ok "the file's owner and mode are untouched (600 op:op)" \
  || bad "block add changed the file: $mode"

# Nothing was granted, so the broker's own account gained nothing either.
if runuser -u faramir-broker -- test -r $KEY 2>/dev/null; then
  bad "the broker can read a refused file, so something granted it access"
else
  ok "the broker's own account cannot read it, nothing having been granted"
fi

# The value is not in the redactor. Asserted positively: the value has to come
# back unchanged, or its absence would prove nothing.
out=$(printf '%s\n' "$KEY_VALUE" | asop redact 2>/dev/null)
if grep -qF "$KEY_VALUE" <<<"$out"; then
  ok "the value is not redacted, faramir never having read it"
elif grep -q 'SECRET:' <<<"$out"; then
  bad "the value was tokenised, so faramir is holding a value it must not: $out"
else
  bad "redact returned neither the value nor a token, so this asserts nothing: $out"
fi

# The other route to the same file, which no rule file reaches. The deny rules
# and the guard cover the agent's own tools and its own shell; `faramir run` is
# neither, so the broker holds the entries itself.
#
# The fixture is world-readable on purpose. A 0600 file would be refused by its
# own mode and this would prove nothing about faramir: what has to be shown is
# the broker refusing a read the executor's uid could have carried out. Under
# /etc rather than the home, which is 710, so the home's mode is not what
# answers either. /etc is where a host keyfile of this kind actually sits.
WORLD=/etc/refused-world.key
WORLD_VALUE=luks_refused_e2e_world_0002
printf '%s\n' "$WORLD_VALUE" > $WORLD
chmod 644 $WORLD
block add --path "$WORLD" >/dev/null 2>&1

out=$(brokered -- /bin/cat $WORLD)
if grep -qF "$WORLD_VALUE" <<<"$out"; then
  bad "*** a brokered command read the blocked file in the clear ***"
elif grep -q 'SECRET:' <<<"$out"; then
  bad "the value came back tokenised, so faramir is holding a value it never read"
else
  ok "a brokered read of a blocked path is refused, and no value came back"
fi
grep -qF "$WORLD" <<<"$out" \
  && ok "and the refusal names the entry that matched" \
  || bad "the refusal does not say which entry stopped it: ${out:0:140}"

# A separator inside an argument, which the program receives as a word rather
# than as a break between two commands. `cat ';' <path>` reports the ';' as a
# missing file and prints the key anyway, so a check that read the argv as a
# shell line would hand the value back through it.
out=$(brokered -- /bin/cat ';' $WORLD)
grep -qF "$WORLD_VALUE" <<<"$out" \
  && bad "*** a separator argument walked a brokered read past the entry ***" \
  || ok "and a separator inside an argument does not split the command"

# What the refusal deliberately does not cover. A brokered command runs where an
# operator asked for it, so managing the file is ordinary work: none of this
# puts a byte of it into the conversation, and refusing it would take out the
# converge that rotates the key.
#
# On a second fixture, because $WORLD cannot answer this one whatever the policy
# says: the executor runs under ProtectSystem=strict with /home as its only
# writable tree, so a chmod under /etc is EROFS, and chmod needs ownership, so
# the file has to be the executor's. Declared the same way, and read back after,
# so a refusal and a sandbox both show as a failure here rather than one hiding
# the other.
printf '%s\n' "$WORLD_VALUE" > $MANAGED
chown faramir-exec:faramir-exec $MANAGED
chmod 644 $MANAGED
block add --path "$MANAGED" >/dev/null 2>&1
brokered -- /bin/chmod 0640 $MANAGED >/dev/null 2>&1 \
  && ok "and changing its mode where it stands is still allowed" \
  || bad "a brokered chmod of a blocked path was refused, which breaks managing it"
[ "$(stat -c %a $MANAGED)" = 640 ] || bad "the chmod did not take effect"
out=$(brokered -- /bin/cat $MANAGED)
grep -qF "$WORLD_VALUE" <<<"$out" \
  && bad "*** the manageable fixture was readable, so it declares nothing ***" \
  || ok "while reading that same file is refused, the entry being an ordinary one"
block rm --path "$MANAGED" >/dev/null 2>&1
rm -f $MANAGED

# And what would be the same disclosure one step later: the contents under a
# name no rule was written for.
out=$(brokered -- /bin/mv $WORLD /tmp/moved-key)
if [ -f /tmp/moved-key ]; then
  bad "*** a brokered mv walked the blocked file out from under its rule ***"
  rm -f /tmp/moved-key
else
  ok "and moving it out from under the rule is refused with the reads"
fi
block rm --path "$WORLD" >/dev/null 2>&1
rm -f $WORLD

# The stricter reading, asked for per entry. The default leaves a declared file
# manageable, which is what a key being rotated needs; this is the directory the
# agent has no business in at all, where a listing is as unwelcome as a read.
STRICT=/etc/refused-strict
mkdir -p $STRICT
printf 'x\n' > $STRICT/notes
chmod -R 755 $STRICT
block add --path "$STRICT" --strict >/dev/null 2>&1
grep -q 'strict = true' $CFG \
  && ok "--strict is recorded on the entry" \
  || bad "the config carries no strict key: $(grep -A2 "$STRICT" $CFG | tr '\n' ' ')"

out=$(brokered -- /bin/ls -l $STRICT)
grep -q 'notes' <<<"$out" \
  && bad "a brokered listing of a --strict path came back: ${out:0:120}" \
  || ok "and a brokered command may not even list it"
out=$(brokered -- /bin/chmod 0700 $STRICT)
[ "$(stat -c %a $STRICT)" = 755 ] \
  && ok "and may not chmod it either, which is the cost the flag names" \
  || bad "a chmod of a --strict path took effect"

# The entry beside it keeps the looser reading: one flag on one entry, not a
# mode the install is in. The manageable fixture again, the strict entry still
# standing, so what is measured is the flag's reach and not the sandbox's.
printf '%s\n' "$WORLD_VALUE" > $MANAGED
chown faramir-exec:faramir-exec $MANAGED
chmod 644 $MANAGED
block add --path "$MANAGED" >/dev/null 2>&1
brokered -- /bin/chmod 0640 $MANAGED >/dev/null 2>&1 \
  && ok "while an ordinary entry on the same host can still be managed" \
  || bad "the strict entry changed how an ordinary one is matched"
block rm --path "$MANAGED" >/dev/null 2>&1
rm -f $MANAGED
block rm --path "$STRICT" >/dev/null 2>&1
rm -rf $STRICT

# --------------------------------------------------------------------------
head_ "4. a path that is not there"
out=$(block add --path "$ABSENT")
grep -q 'not there' <<<"$out" \
  && ok "an absent path is recorded and reported as absent" \
  || bad "adding an absent path said nothing about it: ${out:0:160}"
grep -q "$ABSENT" $CFG \
  && ok "and the entry is written anyway, the rule holding when the volume mounts" \
  || bad "the entry for an absent path was not written"
[ -f $RULES ] && grep -qF "Read($ABSENT)" $RULES \
  && ok "and the rule is rendered for it" \
  || bad "no rule was rendered for the absent path"

# --------------------------------------------------------------------------
head_ "5. a directory refuses what is under it"
out=$(block add --path "$SSHDIR")
grep -q "blocked $SSHDIR" <<<"$out" \
  && ok "a directory is accepted" \
  || bad "block add on a directory: ${out:0:160}"
if [ -f $RULES ]; then
  grep -qF "Read($SSHDIR)" $RULES \
    && ok "the directory itself is refused" \
    || bad "no rule for the directory"
  grep -qF "Read($SSHDIR/**)" $RULES \
    && ok "and so is everything under it, which is where the keys are" \
    || bad "no rule reaches under the directory: a key inside it is still readable"
else
  bad "no rule file at $RULES, so nothing here was checked"
fi

# --------------------------------------------------------------------------
head_ "6. doctor"
# The JSON report rather than the table, where a detail wraps across lines and a
# grep for a phrase would match on where the wrap happened to fall.
# shellcheck disable=SC2034  # read by lib.sh's snap, st and dt
JSON=/tmp/refuse-doctor.json
snap
[ "$(st 'blocked paths')" = ok ] \
  && ok "doctor is OK on the blocked paths with the rules in place" \
  || bad "blocked paths is [$(st 'blocked paths')]: $(dt 'blocked paths')"

# The state the check exists for: the entry in the config and no rule naming
# it, which is the whole of what the entry does gone missing.
cp -a $RULES "$BACKUP/settings.json"
python3 - "$RULES" "$KEY" <<'STRIP'
import json, sys
path, key = sys.argv[1], sys.argv[2]
doc = json.load(open(path))
deny = doc.get("permissions", {}).get("deny", [])
doc["permissions"]["deny"] = [r for r in deny if key not in r]
json.dump(doc, open(path, "w"), indent=2)
STRIP
snap
[ "$(st 'blocked paths')" = failed ] \
  && ok "a rule taken out of the settings is a failure, not a warning" \
  || bad "blocked paths is [$(st 'blocked paths')] with the rule gone: $(dt 'blocked paths')"
dt 'blocked paths' | grep -qF "$KEY" \
  && ok "and the finding names the path that lost its rule" \
  || bad "the finding does not name $KEY: $(dt 'blocked paths')"
cp -a "$BACKUP/settings.json" $RULES
snap
[ "$(st 'blocked paths')" = ok ] \
  && ok "and it is OK again once the rule is back" \
  || bad "blocked paths stayed [$(st 'blocked paths')] after the rule was restored"

# --------------------------------------------------------------------------
head_ "7. init re-asserts what refuse wrote"
# The round trip that makes config.toml the entries' home. A plain `init` that
# did not read them back would drop every rule they render.
"$faramir" init --agent-user op >/dev/null 2>&1
grep -q "$KEY" $CFG \
  && ok "a plain init keeps the entries" \
  || bad "init erased the blocked paths"
[ -f $RULES ] && grep -qF "Read($KEY)" $RULES \
  && ok "and renders their rules again" \
  || bad "init did not render the rule"

# --------------------------------------------------------------------------
head_ "8. the two kinds of entry share one config"
# Both live in config.toml and every write rewrites the whole file from the
# layout, so each has to survive the other being changed. A `block add` that
# dropped the links would take their values out of the redactor, which is the
# quietest way this feature could break the other one.
LINKDIR=/home/op/.config/gh
LINKFILE=$LINKDIR/hosts.yml
LINK_VALUE=gho_refuse_suite_value_0003
install -d -o op -g op -m 0755 $LINKDIR
cat > $LINKFILE <<YAML
github.com:
    oauth_token: $LINK_VALUE
YAML
chown op:op $LINKFILE
# The arrangement a link needs, which faramir checks and does not apply.
chgrp "$(id -gn faramir-broker)" $LINKFILE
chmod 640 $LINKFILE
"$faramir" link add gh/refuse-suite $LINKFILE \
  --type yaml --key github.com/oauth_token >/dev/null 2>&1
waitfor 25 asop refs >/dev/null 2>&1
if asop refs 2>/dev/null | grep -q 'faramir://gh/refuse-suite'; then
  ok "a link is serving beside the blocked paths"
  block add --path /etc/beside-a-link.key >/dev/null 2>&1
  grep -q 'gh/refuse-suite' $CFG \
    && ok "and block add leaves its entry in config.toml" \
    || bad "block add erased the [[secret.link]] entry"
  waitfor 25 asop refs >/dev/null 2>&1
  asop refs 2>/dev/null | grep -q 'faramir://gh/refuse-suite' \
    && ok "and the ref is still served, so the value is still redacted" \
    || bad "the linked ref stopped being served after a block add"
  block rm --path /etc/beside-a-link.key >/dev/null 2>&1
else
  bad "the link never started serving, so this section asserts nothing"
fi
"$faramir" link rm gh/refuse-suite >/dev/null 2>&1
rm -rf $LINKDIR

# --------------------------------------------------------------------------
head_ "9. adding what is already there"
# A configuration manager names every entry on every run, so a second add is the
# ordinary case rather than a mistake: the entry stands and the rules are
# rendered again.
before=$(cat $CFG)
out=$(block add --path "$KEY" --json)
rc=$?
[ $rc -eq 0 ] \
  && ok "a path this install already refuses is not an error" \
  || bad "a second add exited $rc: ${out:0:200}"
grep -q '"changed": false' <<<"$out" \
  && ok "and reports no change, nothing having been written" \
  || bad "a second add reported a change: ${out:0:200}"
[ "$(cat $CFG)" = "$before" ] \
  && ok "the config is byte-identical" \
  || bad "a second add rewrote the config"

# What the re-rendering is for: an agent's settings are the operator's own file,
# and a rule can leave one without faramir being involved.
cp -a $RULES "$BACKUP/settings.json"
printf '{}\n' > $RULES
chown op:op $RULES
block add --path "$KEY" >/dev/null 2>&1
grep -qF "Read($KEY)" $RULES \
  && ok "and a rule that left the agent's settings comes back" \
  || bad "the rule was not restored to $RULES"

# --------------------------------------------------------------------------
head_ "10. ls and rm"
out=$(block ls)
grep -q "$KEY" <<<"$out" && grep -q "$ABSENT" <<<"$out" \
  && ok "block ls lists the entries" \
  || bad "block ls: ${out:0:200}"
block ls --json | jq -e --arg p "$ABSENT" \
  'any(.[]; .entry == $p and .state == "not there")' >/dev/null \
  && ok "and --json says which path is not there" \
  || bad "block ls --json does not report the absent path's state"
asop block ls >/dev/null 2>&1 \
  && ok "and needs no root, reading only the config" \
  || note "block ls as the agent's account was refused (the guard denies it in a shell)"

out=$(block rm --path "$ABSENT")
grep -q "stopped blocking $ABSENT" <<<"$out" \
  && ok "block rm reports what it removed" \
  || bad "block rm: ${out:0:160}"
grep -q "$ABSENT" $CFG \
  && bad "the entry is still in config.toml" \
  || ok "the entry is gone from config.toml"
grep -q 'deny rule' <<<"$out" \
  && ok "and says the deny rule naming it stays, a merged file only being addable to" \
  || bad "removal does not say the rule stays: ${out:0:160}"

before=$(cat $CFG)
out=$(block rm --path /no/such/path 2>&1)
rc=$?
[ $rc -eq 0 ] \
  && ok "removing a path this install does not refuse is not an error" \
  || bad "block rm on an unknown path exited $rc: ${out:0:160}"
grep -q 'faramir block ls' <<<"$out" \
  && ok "and names the command that lists the ones it does" \
  || bad "block rm on an unknown path: ${out:0:160}"
[ "$(cat $CFG)" = "$before" ] \
  && ok "and writes nothing" \
  || bad "removing a path that is not refused rewrote the config"

# --------------------------------------------------------------------------
head_ "11. a declared directory"
#
# The entry a list of file names cannot stand in for: a directory covers what is
# under it, including the files nobody enumerated. Asserted on the rendered rule
# rather than on a tool being refused, that rule being the whole of what the
# entry does.
NAME=/tmp/e2e-keys
mkdir -p "$NAME"
out=$(block add --path "$NAME")
grep -qF "blocked $NAME" <<<"$out" \
  && ok "block add --path takes a directory" \
  || bad "block add --path printed no confirmation: ${out:0:200}"
grep -qF "path = \"$NAME\"" $CFG \
  && ok "and the entry is written as a path" \
  || bad "the path entry is not in config.toml"
grep -qF "Read($NAME/**)" $RULES \
  && ok "and the agent's rules cover what is under it" \
  || bad "the subtree rule was not rendered into $RULES"
out=$(block add --path "$NAME")
grep -q 'already blocked' <<<"$out" \
  && ok "adding the same path again is not an error" \
  || bad "a second add of one path: ${out:0:160}"
out=$(block add --path / 2>&1)
grep -q 'every file on the host' <<<"$out" \
  && ok "and the whole filesystem is refused" \
  || bad "'/' was not refused: ${out:0:160}"

block ls --declared | grep -q "$NAME" \
  && ok "block ls --declared lists what the config carries" \
  || bad "--declared does not list the declared path"

# There are no built-in rules, so nothing outside this install's own directories
# is unremovable: removing an entry it does not carry is the no-op it has always
# been.
before=$(cat $CFG)
for path in /tmp/e2e-absent.key /srv/e2e-absent; do
  out=$(block rm --path "$path" 2>&1)
  rc=$?
  [ $rc -eq 0 ] \
    && ok "block rm --path $path is not refused as a built-in" \
    || bad "removing $path exited $rc: ${out:0:200}"
  grep -q 'compiled into faramir' <<<"$out" \
    && bad "$path is still read as a built-in: ${out:0:160}" \
    || ok "and nothing claims faramir carries it"
done
[ "$(cat $CFG)" = "$before" ] \
  && ok "and neither wrote to the config" \
  || bad "removing an entry that is not declared rewrote the config"
# One set, two entry points: the same entry that refuses a file tool refuses a
# command reading it. This is the half a rule file cannot show, so it is put to
# the guard as the agent's own account would meet it.
guard_says() {
  printf '{"tool_name":"Bash","tool_input":{"command":%s}}' "$(printf '%s' "$1" | jq -R .)" |
    runuser -u op -- env HOME=/home/op "$faramir" guard 2>/dev/null
}
guard_says "cat $KEY" | grep -q '"permissionDecision":"deny"' \
  && ok "a declared path is refused to a command as well as to a file tool" \
  || bad "the guard allows a read of the declared $KEY"
guard_says "cat /etc/hostname" | grep -q '"permissionDecision":"deny"' \
  && bad "the guard denies an ordinary read" \
  || ok "and an ordinary read is left alone"

out=$(block ls)
grep -qE '^(path|command) ' <<<"$out" \
  && ok "block ls lists what the config declares" \
  || bad "block ls carries no declared entry: ${out:0:200}"
grep -qE '^[0-9]+ built-in command rule\(s\):' <<<"$out" \
  && ok "and the command rules faramir carries itself" \
  || bad "block ls does not list the command rules: ${out: -300}"
# The table is the declared half alone, so it is sorted the whole way down. A
# built-in row in it would sit where its own half sorted it, which reads as a
# table that lost its order partway.
head -1 <<<"$out" | grep -q '^KIND' \
  || bad "block ls printed no table, so the rows below are another section"
rows=$(sed -n '2,/^$/p' <<<"$out" | sed '/^$/d')
[ "$rows" = "$(LC_ALL=C sort <<<"$rows")" ] \
  && ok "and the table is sorted from its first row to its last" \
  || bad "block ls is out of order: $(diff <(echo "$rows") <(LC_ALL=C sort <<<"$rows") | head -c 200)"
# A row is a path or a command and nothing else. Where a rule is enforced
# follows from the kind rather than being carried in a column beside it, and a
# rendering shape is never a kind.
grep -qE '^(suffix|prefix|dir|glob|name) ' <<<"$out" \
  && bad "block ls reports a shape or a name as a kind: ${out:0:200}" \
  || ok "and every row is a path or a command"
grep -q 'file tools, commands' <<<"$out" \
  && bad "block ls still carries a covers column: ${out:0:200}" \
  || ok "and carries no column for where a rule is enforced"
block ls --declared | grep -q 'command rule(s)' \
  && bad "--declared listed the command rules" \
  || ok "and --declared is the config's own half"
# The other half, which no entry declares and no block rm removes.
out=$(block ls --built-in)
grep -q "$KEY" <<<"$out" \
  && bad "--built-in listed a declared entry: ${out:0:200}" \
  || ok "and --built-in is the half faramir renders itself"
# Under a heading of their own rather than as table rows: the declared half and
# this one are sorted separately, so one table holding both reads as unsorted.
grep -qE '^[0-9]+ built-in path rule\(s\):' <<<"$out" \
  && ok "under a heading saying they are faramir's own" \
  || bad "--built-in heads its paths with nothing: ${out:0:200}"
grep -qE '^  /etc/faramir$' <<<"$out" \
  && ok "which names this install's own directories" \
  || bad "--built-in names no install directory: ${out:0:200}"
[ -n "$(head -1 <<<"$out")" ] \
  && ok "and opens on the heading rather than a blank line" \
  || bad "--built-in opens on a blank line: [${out:0:80}]"
# The two renderings are one listing. A row the text prints under a heading and
# the JSON calls declared is a row an operator would try to `block rm`.
full=$(block ls)
sections=$(grep -oE '^[0-9]+ built-in' <<<"$full" | awk '{s+=$1} END{print s+0}')
# The table only, which the KIND header opens and the first blank line closes.
declared_rows=$(head -1 <<<"$full" | grep -q '^KIND' \
  && sed -n '2,/^$/p' <<<"$full" | sed '/^$/d' | wc -l || echo 0)
json_built=$(block ls --json | jq '[.[]|select(.source=="built-in")]|length')
json_declared=$(block ls --json | jq '[.[]|select(.source=="declared")]|length')
[ "$sections" = "$json_built" ] \
  && ok "the text sections hold every built-in the JSON reports ($sections)" \
  || bad "text sections total $sections, JSON reports $json_built built-in"
[ "$declared_rows" = "$json_declared" ] \
  && ok "and the table holds every declared entry ($declared_rows)" \
  || bad "table has $declared_rows rows, JSON reports $json_declared declared"
out=$(block ls --declared --built-in 2>&1); code=$?
[ $code -eq 2 ] \
  && ok "and naming both halves is refused, being the default" \
  || bad "--declared --built-in: exit $code [${out:0:120}]"

# A command entry: the other form, which reaches the guard and no rule file.
out=$(block add --command 'e2e-probe read')
grep -q 'blocked e2e-probe read' <<<"$out" \
  && ok "block add --command writes an entry" \
  || bad "block add --command: ${out:0:200}"
grep -qF "command = \"e2e-probe read\"" $CFG \
  && ok "and the config carries it as a command" \
  || bad "the command entry is not in config.toml"
guard_says "e2e-probe read thing" | grep -q '"permissionDecision":"deny"' \
  && ok "and the agent's shell is refused it, without a later init" \
  || bad "the guard allows the declared command"
grep -qF 'e2e-probe' /usr/local/libexec/faramir/deny-patterns.txt \
  && ok "the add rendered the file the guard reads" \
  || bad "deny-patterns.txt does not carry the entry the add reported"
grep -q 'is not there' <<<"$out" \
  && bad "a command entry was stat'ed as a path: ${out:0:200}" \
  || ok "and the add warns about the command rather than an empty path"
guard_says "e2e-probe-other read" | grep -q '"permissionDecision":"deny"' \
  && bad "the guard denies a longer word starting the same way" \
  || ok "and a neighbouring command is left alone"
guard_says "grep -rn 'e2e-probe read' /etc/faramir/config.toml" |
  grep -q '"permissionDecision":"deny"' \
  && bad "the guard denies a search that only names the command" \
  || ok "and a line naming it without running it, which is how the list is edited"
guard_says "sudo e2e-probe read thing" | grep -q '"permissionDecision":"deny"' \
  && ok "and it is refused behind sudo, where a command still starts" \
  || bad "the guard allows the declared command behind sudo"
# The same command, spelled with the path the program is at. An operator naming
# `e2e-probe read` means the program, and the spelling an agent reaches for
# after meeting the refusal must not be the one that is not refused.
guard_says "/usr/local/bin/e2e-probe read thing" | grep -q '"permissionDecision":"deny"' \
  && ok "and by absolute path, which is the same command" \
  || bad "the guard allows the declared command named by path"
guard_says "./e2e-probe read thing" | grep -q '"permissionDecision":"deny"' \
  && ok "and relative to the working directory" \
  || bad "the guard allows the declared command named relatively"
guard_says "/usr/local/bin/e2e-probe-other read" | grep -q '"permissionDecision":"deny"' \
  && bad "the path prefix widened onto a neighbouring command" \
  || ok "while a neighbour by path is still a different program"
grep -qF 'e2e-probe' $RULES \
  && bad "a command entry reached the agent's file-tool rules" \
  || ok "and it reaches no rule file, a command not being a path"
block rm --command 'e2e-probe read' >/dev/null 2>&1

# Six `block add` at once. Each reads config.toml, adds its entry and writes the
# whole file back, so without a check the last writer wins and the other five
# report an entry they did not leave behind.
rm -f /tmp/conc.*.rc
for i in 1 2 3 4 5 6; do
  ( block add --path "/srv/e2e-conc$i" >/dev/null 2>&1; echo $? > /tmp/conc.$i.rc ) &
done
wait
# Per entry, not by count. An add writes config.toml and then re-renders the
# deny patterns and the agent's rule files, so one that collides on those exits
# non-zero with its entry already written: more may land than reported success,
# and a retry of that one is a no-op. What must never happen is the other way
# round -- an add that reported success and left nothing.
declared=$(block ls --declared 2>/dev/null)
lost=0; landed=0
for i in 1 2 3 4 5 6; do
  grep -q '/srv/e2e-conc'"$i"'$' <<<"$declared" && landed=$((landed + 1)) && continue
  [ "$(cat /tmp/conc.$i.rc)" = 0 ] && lost=$((lost + 1))
done
[ "$lost" -eq 0 ] \
  && ok "every concurrent add that reported success left its entry ($landed of six landed)" \
  || bad "$lost concurrent add(s) reported success and left nothing behind"
[ "$landed" -ge 1 ] && ok "  and at least one got through" \
  || bad "  none of six concurrent adds landed"
out=$(block add --path /srv/e2e-conc1 2>&1)
grep -qE 'already there|changed while this was working' <<<"$out" \
  || ok "  a serial add after them is unaffected"
for i in 1 2 3 4 5 6; do block rm --path "/srv/e2e-conc$i" >/dev/null 2>&1; done
rm -f /tmp/conc.*.rc

# A path the install's own layout also covers. Taking the entry back leaves the
# path blocked, and saying nothing would read as the file becoming readable.
INSIDE=/etc/faramir/secrets/e2e-inside.sops.yml
block add --path "$INSIDE" >/dev/null 2>&1
out=$(block rm --path "$INSIDE")
grep -q "$INSIDE" <<<"$out" \
  && ok "block rm removes an entry the layout also covers" \
  || bad "block rm of a covered path: ${out:0:200}"
grep -q '/etc/faramir' <<<"$out" \
  && ok "and names the directory that still blocks it" \
  || bad "the removal says nothing about what still blocks it: ${out:0:300}"
out=$(block rm --path /etc/faramir/age.key 2>&1); code=$?
[ $code -eq 1 ] && grep -q 'block ls' <<<"$out" \
  && ok "and a path only the layout blocks cannot be removed at all" \
  || bad "block rm of an undeclared covered path: exit $code [${out:0:200}]"

out=$(block rm --path "$NAME")
grep -qF "stopped blocking $NAME" <<<"$out" \
  && ok "block rm --path removes it" \
  || bad "block rm --path: ${out:0:160}"
grep -qF "path = \"$NAME\"" $CFG \
  && bad "the path entry is still in config.toml" \
  || ok "and the entry is gone from config.toml"

head_ "12. an entry a rule cannot carry"

# A rendered rule is one line of a generated file and the entry is written into
# it, so a newline ends that rule and starts a second line with the rest. Both
# halves are unbalanced expressions the guard cannot compile, and a rule that
# does not compile is skipped: the entry meant to refuse one more file takes the
# rules protecting the install with it, and a doctor that re-renders and
# compares cannot see it, the file agreeing with itself.
RULES=/usr/local/libexec/faramir/deny-patterns.txt
rules_now() { grep -cvE '^\s*(#|$)' $RULES; }
before_rules=$(rules_now)

out=$(block add --command "$(printf 'aa\nbb')"); code=$?
[ $code -ne 0 ] && grep -q 'control\|carries' <<<"$out" \
  && ok "block add --command refuses an entry carrying a newline" \
  || bad "block add --command took a newline: exit $code [${out:0:200}]"
out=$(block add --path "$(printf '/tmp/aa\nbb')"); code=$?
[ $code -ne 0 ] \
  && ok "and so does the path form" \
  || bad "block add PATH took a newline: exit $code [${out:0:200}]"

# The rest of the controls do not split a rule; they are refused because a
# listing prints an entry back to a terminal, which acts on them.
# $'' so these are the bytes themselves rather than two characters each.
ctl_names=('carriage return' 'ESC c' 'BEL')
ctl_bytes=($'\r' $'\ec' $'\a')
for i in 0 1 2; do
  out=$(block add --path "/tmp/aa${ctl_bytes[$i]}bb"); code=$?
  [ $code -ne 0 ] \
    && ok "and an entry carrying a ${ctl_names[$i]} is refused" \
    || bad "block add --path took a ${ctl_names[$i]}: exit $code"
done

[ "$(rules_now)" = "$before_rules" ] \
  && ok "so the rendered file still carries its $before_rules rule(s)" \
  || bad "the rule count moved from $before_rules to $(rules_now)"

# The consequence, stated as behaviour: the rules that protect the install are
# the ones a split takes out, so they are what is asserted afterwards.
for target in /etc/faramir/age.key /var/log/faramir/audit.log; do
  guard_says "cat $target" | grep -q '"permissionDecision":"deny"' \
    && ok "and $target is still refused" \
    || bad "the guard allows a read of $target"
done

# Every rendered rule compiles, which is the check doctor makes and the one a
# re-render cannot: a skipped rule refuses nothing and the file still matches
# itself. Asked of doctor rather than of another regexp engine, so the question
# is put to the one that decides it.
out=$("$faramir" doctor 2>&1 | grep 'deny patterns')
grep -q '^ok' <<<"$out" \
  && ok "doctor finds every rendered rule compiles" \
  || bad "doctor on the rendered rules: ${out:0:200}"

# And a listing prints an entry back to a terminal, which obeys what it is sent.
block ls | grep -qP '[\x00-\x08\x0b\x0c\x0e-\x1f]' \
  && bad "block ls sent a control character to the terminal" \
  || ok "block ls sends the terminal nothing it would act on"

head_ "13. the spellings a shell expands to the same file"

# A path rule is a literal, and the tilde is how a person and a model both name
# a file under a home: without the other spellings `cat ~/.luks/luks.key`
# reaches a file that the absolute spelling is refused. That is the accident
# this list exists to catch, not the evasion it does not claim to stop.
block add --path "$KEY" >/dev/null 2>&1
REL=${KEY#/home/op/}
# Built rather than written inline: each of these has to reach the guard as the
# literal text a shell would have expanded, so none of them may expand here.
TILDE='~'
DOLLAR_HOME='$HOME'
BRACED_HOME='${HOME}'
for spelling in "$KEY" "$TILDE/$REL" "$DOLLAR_HOME/$REL" "$BRACED_HOME/$REL"; do
  guard_says "cat $spelling" | grep -q '"permissionDecision":"deny"' \
    && ok "cat $spelling is refused" \
    || bad "cat $spelling reaches the declared $KEY"
done
guard_says "rm -rf $TILDE/$REL" | grep -q '"permissionDecision":"deny"' \
  && ok "and a write through the tilde spelling too" \
  || bad "rm -rf $TILDE/$REL is allowed"

# The bound still holds: a neighbour that merely starts the same way, and an
# ordinary file under the same home, are both left alone.
for spelling in "$TILDE/.luksier/x" "$TILDE/notes.md"; do
  guard_says "cat $spelling" | grep -q '"permissionDecision":"deny"' \
    && bad "cat $spelling is refused by a rule about a neighbouring path" \
    || ok "and cat $spelling is left alone"
done
block rm --path "$KEY" >/dev/null 2>&1

summary

#!/bin/bash
# A path the agent's file tools are refused and faramir never reads:
# [[secret.refuse]].
#
# The weaker of the two entries a file can get, and the one thing only a real
# install can show is exactly where that weakness sits. A link draws three
# boundaries; this draws one, and a suite that checked only the deny rule would
# report the two as the same feature.
#
# So the deny rule is asserted, and then the two things it deliberately does not
# do are asserted just as hard: the file's mode is left alone, and the value is
# absent from the redactor. Both are the documented trade rather than gaps, and
# a change that quietly closed one would be a change that started reading the
# file.
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
# The account-wide rule file, and whether this suite is what created the marker
# that makes `--agent auto` write one. Declared before the trap that reads it.
CLAUDE_HOME=/home/op/.claude
RULES=/home/op/.claude/settings.json
MADE_CLAUDE_HOME=

faramir=/usr/local/bin/faramir
asop() { runuser -u op -- env HOME=/home/op "$faramir" "$@"; }
brokered() { asop run --quiet -t 25 "$@" 2>&1; }
# `faramir refuse` as an operator runs it. --agent-user because this suite runs
# as root with no SUDO_USER to carry it.
refuse() { "$faramir" refuse --agent-user op "$@" 2>&1; }

# This suite writes entries into a shared install and renders them into the
# operator's rule files. Later suites read both, so put the config back and take
# the entries out again.
BACKUP=$(mktemp -d)
cp -a $CFG "$BACKUP/config.toml"
restore_baseline() {
  local rc=$?
  for path in "$KEY" "$ABSENT" "$SSHDIR"; do
    "$faramir" refuse rm --agent-user op "$path" >/dev/null 2>&1 || true
  done
  cp -a "$BACKUP/config.toml" $CFG
  # Section 9 empties the rule file to check that a re-add restores it.
  [ -f "$BACKUP/settings.json" ] && cp -a "$BACKUP/settings.json" $RULES
  rm -rf "$BACKUP" "$KEYDIR" "$SSHDIR"
  rm -f /etc/refused-world.key
  "$faramir" link rm --agent-user op gh/refuse-suite >/dev/null 2>&1 || true
  "$faramir" refuse rm --agent-user op /etc/beside-a-link.key >/dev/null 2>&1 || true
  rm -rf /home/op/.config/gh
  [ -n "$MADE_CLAUDE_HOME" ] && rm -rf "$CLAUDE_HOME"
  "$faramir" reload >/dev/null 2>&1 || true
  waitfor 25 asop refs >/dev/null 2>&1 || true
  return "$rc"
}
trap restore_baseline EXIT

# The account-wide rule files are what a [[secret.refuse]] entry renders into,
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
# There is no grant and no probe here, so these are the only ways `refuse add`
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
  out=$(refuse add "$path" 2>&1)
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
out=$(refuse add "$KEY")
grep -q "refused $KEY" <<<"$out" \
  && ok "refuse add reports what it refused" \
  || bad "refuse add: ${out:0:160}"

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
  || bad "refuse add changed the file: $mode"

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

# And the consequence, which is the honest limit of the feature and the reason
# `link` exists beside it: the deny rule stops the agent's own file tools, not a
# command the broker runs. Asserted rather than noted, against a file whose mode
# lets the executor read it, or the fixture's own 600 would be what refused the
# read and this would prove nothing about faramir.
#
# It reads as an assertion that the value leaks, and it is. A change that made
# this fail would be a change that started regrouping the file or holding its
# value, and the documented trade would need rewriting with it.
# Under /etc rather than the home, which is 710: a brokered command cannot
# traverse into the operator's home whatever a file inside it is set to, so a
# fixture there would be refused by the home's own mode and would prove nothing.
# /etc is where a host keyfile of this kind actually sits.
WORLD=/etc/refused-world.key
WORLD_VALUE=luks_refused_e2e_world_0002
printf '%s\n' "$WORLD_VALUE" > $WORLD
chmod 644 $WORLD
refuse add "$WORLD" >/dev/null 2>&1
out=$(brokered -- /bin/cat $WORLD)
if grep -qF "$WORLD_VALUE" <<<"$out"; then
  ok "a brokered command still reads a refused file, in the clear: only the agent's own tools are stopped"
elif grep -q 'SECRET:' <<<"$out"; then
  bad "the value came back tokenised, so faramir is holding a value it never read"
else
  bad "the brokered read neither returned the value nor a token: ${out:0:140}"
fi
refuse rm "$WORLD" >/dev/null 2>&1
rm -f $WORLD

# --------------------------------------------------------------------------
head_ "4. a path that is not there"
out=$(refuse add "$ABSENT")
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
out=$(refuse add "$SSHDIR")
grep -q "refused $SSHDIR" <<<"$out" \
  && ok "a directory is accepted" \
  || bad "refuse add on a directory: ${out:0:160}"
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
JSON=/tmp/refuse-doctor.json
snap() { "$faramir" doctor --agent-user op --json >$JSON 2>/dev/null; }
st() { jq -r --arg c "$1" '[.findings[]|select(.check==$c)|.status]|join(",")' $JSON; }
dt() { jq -r --arg c "$1" '[.findings[]|select(.check==$c)|.detail]|join(" ")' $JSON; }
snap
[ "$(st 'refused paths')" = ok ] \
  && ok "doctor is OK on the refused paths with the rules in place" \
  || bad "refused paths is [$(st 'refused paths')]: $(dt 'refused paths')"

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
[ "$(st 'refused paths')" = failed ] \
  && ok "a rule taken out of the settings is a failure, not a warning" \
  || bad "refused paths is [$(st 'refused paths')] with the rule gone: $(dt 'refused paths')"
dt 'refused paths' | grep -qF "$KEY" \
  && ok "and the finding names the path that lost its rule" \
  || bad "the finding does not name $KEY: $(dt 'refused paths')"
cp -a "$BACKUP/settings.json" $RULES
snap
[ "$(st 'refused paths')" = ok ] \
  && ok "and it is OK again once the rule is back" \
  || bad "refused paths stayed [$(st 'refused paths')] after the rule was restored"

# --------------------------------------------------------------------------
head_ "7. init re-asserts what refuse wrote"
# The round trip that makes config.toml the entries' home. A plain `init` that
# did not read them back would drop every rule they render.
"$faramir" init --agent-user op >/dev/null 2>&1
grep -q "$KEY" $CFG \
  && ok "a plain init keeps the entries" \
  || bad "init erased the refused paths"
[ -f $RULES ] && grep -qF "Read($KEY)" $RULES \
  && ok "and renders their rules again" \
  || bad "init did not render the rule"

# --------------------------------------------------------------------------
head_ "8. the two kinds of entry share one config"
# Both live in config.toml and every write rewrites the whole file from the
# layout, so each has to survive the other being changed. A `refuse add` that
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
chmod 600 $LINKFILE
"$faramir" link add --agent-user op gh/refuse-suite $LINKFILE \
  --type yaml --key github.com/oauth_token >/dev/null 2>&1
waitfor 25 asop refs >/dev/null 2>&1
if asop refs 2>/dev/null | grep -q 'faramir://gh/refuse-suite'; then
  ok "a link is serving beside the refused paths"
  refuse add /etc/beside-a-link.key >/dev/null 2>&1
  grep -q 'gh/refuse-suite' $CFG \
    && ok "and refuse add leaves its entry in config.toml" \
    || bad "refuse add erased the [[secret.link]] entry"
  waitfor 25 asop refs >/dev/null 2>&1
  asop refs 2>/dev/null | grep -q 'faramir://gh/refuse-suite' \
    && ok "and the ref is still served, so the value is still redacted" \
    || bad "the linked ref stopped being served after a refuse add"
  refuse rm /etc/beside-a-link.key >/dev/null 2>&1
else
  bad "the link never started serving, so this section asserts nothing"
fi
"$faramir" link rm --agent-user op gh/refuse-suite >/dev/null 2>&1
rm -rf $LINKDIR

# --------------------------------------------------------------------------
head_ "9. adding what is already there"
# A configuration manager names every entry on every run, so a second add is the
# ordinary case rather than a mistake: the entry stands and the rules are
# rendered again.
before=$(cat $CFG)
out=$(refuse add "$KEY" --json)
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
refuse add "$KEY" >/dev/null 2>&1
grep -qF "Read($KEY)" $RULES \
  && ok "and a rule that left the agent's settings comes back" \
  || bad "the rule was not restored to $RULES"

# --------------------------------------------------------------------------
head_ "10. ls and rm"
out=$(refuse ls)
grep -q "$KEY" <<<"$out" && grep -q "$ABSENT" <<<"$out" \
  && ok "refuse ls lists the entries" \
  || bad "refuse ls: ${out:0:200}"
grep -q 'not there' <<<"$out" \
  && ok "and says which path is not there" \
  || bad "refuse ls does not report the absent path's state: ${out:0:200}"
asop refuse ls >/dev/null 2>&1 \
  && ok "and needs no root, reading only the config" \
  || note "refuse ls as the agent's account was refused (the guard denies it in a shell)"

out=$(refuse rm "$ABSENT")
grep -q "stopped refusing $ABSENT" <<<"$out" \
  && ok "refuse rm reports what it removed" \
  || bad "refuse rm: ${out:0:160}"
grep -q "$ABSENT" $CFG \
  && bad "the entry is still in config.toml" \
  || ok "the entry is gone from config.toml"
grep -q 'deny rule' <<<"$out" \
  && ok "and says the deny rule naming it stays, a merged file only being addable to" \
  || bad "removal does not say the rule stays: ${out:0:160}"

before=$(cat $CFG)
out=$(refuse rm /no/such/path 2>&1)
rc=$?
[ $rc -eq 0 ] \
  && ok "removing a path this install does not refuse is not an error" \
  || bad "refuse rm on an unknown path exited $rc: ${out:0:160}"
grep -q 'faramir refuse ls' <<<"$out" \
  && ok "and names the command that lists the ones it does" \
  || bad "refuse rm on an unknown path: ${out:0:160}"
[ "$(cat $CFG)" = "$before" ] \
  && ok "and writes nothing" \
  || bad "removing a path that is not refused rewrote the config"

# --------------------------------------------------------------------------
head_ "11. a name rather than a path"
#
# The case a path cannot reach: a file the agent names by a path this host does
# not have. Nothing here mounts a container, so the assertion is on the rule
# that was rendered rather than on a tool being refused, that rule being the
# whole of what the entry does.
NAME='*.e2e-htpasswd'
out=$(refuse add --name "$NAME")
grep -qF 'ends in ".e2e-htpasswd"' <<<"$out" \
  && ok "refuse add --name says what the pattern will match" \
  || bad "refuse add --name printed no match description: ${out:0:200}"
grep -qF 'name = "*.e2e-htpasswd"' $CFG \
  && ok "and the entry is written as a name" \
  || bad "the name entry is not in config.toml"
grep -qF 'Read(**/*.e2e-htpasswd)' $RULES \
  && ok "and the agent's rules carry it in their own spelling" \
  || bad "the rule was not rendered into $RULES"
out=$(refuse add --name "$NAME")
grep -q 'already refused' <<<"$out" \
  && ok "adding the same name again is not an error" \
  || bad "a second add of one name: ${out:0:160}"
out=$(refuse add --name '*' 2>&1)
grep -q 'every file on the host' <<<"$out" \
  && ok "and a pattern matching everything is refused" \
  || bad "'*' was not refused: ${out:0:160}"

out=$(refuse ls)
grep -q 'built-in' <<<"$out" \
  && ok "refuse ls lists the rules compiled in beside the declared ones" \
  || bad "refuse ls carries no built-in rules: ${out:0:200}"
grep -qF 'age.key' <<<"$out" \
  && ok "and names one of them" \
  || bad "refuse ls does not name a built-in rule: ${out:0:200}"
refuse ls --declared | grep -q 'built-in' \
  && bad "--declared listed the built-in rules" \
  || ok "and --declared narrows it to what the config carries"

# A rule faramir carries itself is not an entry, so there is nothing to remove
# and the host goes on refusing it. It fails before root is asked for, a request
# that can never be granted having no business costing a sudo first.
before=$(cat $CFG)
out=$(refuse rm --name '*.pem' 2>&1)
rc=$?
[ $rc -ne 0 ] \
  && ok "refuse rm on a built-in rule fails" \
  || bad "removing a built-in exited 0: ${out:0:200}"
grep -q 'compiled into faramir' <<<"$out" \
  && ok "and says where the rule comes from" \
  || bad "the refusal does not name the source: ${out:0:200}"
out=$(refuse rm /home/op/.ssh/id_rsa 2>&1)
rc=$?
[ $rc -ne 0 ] && grep -q 'compiled into faramir' <<<"$out" \
  && ok "and naming a file one covers gets the same answer" \
  || bad "removing a path a built-in covers: ${out:0:200}"
[ "$(cat $CFG)" = "$before" ] \
  && ok "and neither wrote to the config" \
  || bad "a refused removal rewrote the config"

out=$(refuse rm --name "$NAME")
grep -qF "stopped refusing $NAME" <<<"$out" \
  && ok "refuse rm --name removes it" \
  || bad "refuse rm --name: ${out:0:160}"
grep -qF 'name = "*.e2e-htpasswd"' $CFG \
  && bad "the name entry is still in config.toml" \
  || ok "and the entry is gone from config.toml"

summary

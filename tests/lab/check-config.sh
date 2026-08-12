#!/bin/bash
# Changing an install's configuration, which is drop-ins plus reload.
#
# config.toml is init's and is rewritten every run, so everything an operator
# changes goes in /etc/faramir/config.d/*.toml.  Two things make this worth a
# suite: what a drop-in may NOT set, and what happens to a running host when one
# is wrong.
#
# The refusals are the security half.  A drop-in setting [ssh] exec_group to the
# client group hands the broker's SSH identity to the account the relay exists
# to keep it from; one setting [sudo] pam_service chooses what decides every
# approval; one setting [keeper] allowed_user points the age key somewhere else.
# Each is refused by name, and each is checked here one at a time.
#
# Run as root in the lab container.
set -u
CFG=/etc/faramir/config.toml
DROPIN=/etc/faramir/config.d
SECRET='hunter2-correct-horse-battery'
. "$(dirname "$0")/lib.sh" || { echo "lab: lib.sh is missing beside $0" >&2; exit 2; }

drop() { mkdir -p $DROPIN; printf '%s\n' "$2" > "$DROPIN/$1"; }
undrop() { rm -f $DROPIN/*.toml 2>/dev/null; }
# check is the broker's own verdict on what is installed, as the broker's uid.
# JSON on stdout; the reasons go to stderr and are read separately by why().
check() { runuser -u faramir-broker -- /usr/local/bin/faramir broker -c $CFG --check 2>/dev/null; }
# shellcheck disable=SC2069  # stderr to the capture, stdout to null: reading the reasons, not the report
why()   { runuser -u faramir-broker -- /usr/local/bin/faramir broker -c $CFG --check 2>&1 >/dev/null; }
ckcode(){ runuser -u faramir-broker -- /usr/local/bin/faramir broker -c $CFG --check >/dev/null 2>&1; echo $?; }
# settle restarts onto whatever is on disk and waits for the broker to serve.
settle() {
  systemctl reset-failed 'faramir-*' >/dev/null 2>&1
  /usr/local/bin/faramir reload >/dev/null 2>&1
  waitfor 25 runuser -u op -- /usr/local/bin/faramir list-secrets
}

undrop
mkdir -p $DROPIN
echo "config.d is $DROPIN; base config $CFG"

# --------------------------------------------------------------------------
head_ "1. a drop-in changes a default, and reload is what applies it"

drop 10-tune.toml '[secrets]
min_length = 12'
# Parsed straight away by a fresh process, so the file is good.
check >/tmp/c1.json 2>&1
if jq -e '.configs | length >= 2' /tmp/c1.json >/dev/null 2>&1; then
  ok "--check reads the drop-in alongside the base ($(jq -r '.configs|length' /tmp/c1.json) files)"
else
  bad "--check did not read the drop-in: $(jq -c '.configs' /tmp/c1.json 2>/dev/null)"
fi
settle || bad "the host did not come back after reload"
# min_length 12 refuses a value that 8 admitted, which is how the change shows.
n=$(check | jq -r '.secrets.not_redactable | length' 2>/dev/null)
[ "${n:-0}" -ge 1 ] && ok "the drop-in's min_length is in force ($n ref(s) now refused)" \
  || bad "min_length = 12 had no effect (not_redactable = ${n:-?})"
undrop; settle || bad "the host did not come back after removing the drop-in"

# --------------------------------------------------------------------------
head_ "2. the keys a drop-in may not set"
#
# Each is init's, derived from a flag or from the install layout.  A drop-in
# setting one is refused rather than merged, and the refusal names what to run.

refuses() { # section, key, value, why it matters
  local section=$1 key=$2 value=$3 why=$4
  drop 50-owned.toml "[$section]
$key = $value"
  local out; out=$(why)
  undrop
  if grep -qiE "may not|refus|init|is set by" <<<"$out"; then
    ok "[$section] $key is refused ($why)"
  else
    bad "[$section] $key was ACCEPTED from a drop-in ($why): $(grep -iE 'error|refus' <<<"$out" | head -1 | cut -c1-90)"
  fi
}

refuses ssh key '"/tmp/other_key"' "a second identity reaching the same hosts"
refuses ssh exec_group '"dev"' "the group the agent relay admits"
refuses ssh agent_socket '"/tmp/agent.sock"' "where the relay listens"
refuses ssh ssh_agent '"/tmp/fake-agent"' "a program the broker execs"
refuses ssh ssh_add '"/tmp/fake-add"' "a program the broker execs"
refuses server allowed_group '"root"' "who may open the broker socket"
refuses keeper allowed_user '"op"' "who may ask the keeper for a value"
refuses keeper age_key_file '"/tmp/other.key"' "where the master key is read from"
refuses keeper age_key_credential '"other"' "the credential the key arrives under"
refuses executor allowed_user '"op"' "who may ask the executor to fork"
refuses audit log_path '"/tmp/audit.log"' "where the record is written"
refuses sudo exec_user '"op"' "the account the sudo grant is written for"
refuses sudo pam_service '"other-service"' "what decides every approval"
refuses sudo helper '"/tmp/yes"' "the program PAM execs as root"
refuses sudo notify_command '["/tmp/x"]' "a program the broker execs holding every value"

# What the .socket units decide, which a config file cannot move.
refuses server socket_path '"/tmp/broker.sock"' "systemd owns the listening socket"
refuses keeper socket_path '"/tmp/keeper.sock"' "systemd owns the listening socket"
refuses executor socket_path '"/tmp/exec.sock"' "systemd owns the listening socket"

# The refusal has to say what to run instead, or an operator is left guessing.
drop 50-owned.toml '[ssh]
exec_group = "dev"'
out=$(why); undrop
grep -q -- '--exec-user' <<<"$out" && ok "and the refusal names the flag that sets it" \
  || bad "the refusal does not name a flag: $(grep -iE 'exec_group' <<<"$out" | head -1 | cut -c1-110)"

# --------------------------------------------------------------------------
head_ "3. what a drop-in may set, and how two of them combine"

# An inventory accumulates: one entry per owner, so a second drop-in adds
# rather than replacing what the first named.
drop 10-a.toml '[secrets]
patterns = ["/etc/faramir/secrets/a-*.sops.yml"]'
drop 20-b.toml '[secrets]
patterns = ["/etc/faramir/secrets/b-*.sops.yml"]'
out=$(check | jq -r '.secrets.patterns | length' 2>/dev/null)
[ "${out:-0}" -ge 3 ] && ok "two drop-ins and the base give $out patterns: the inventory accumulates" \
  || bad "patterns = ${out:-?}, want the base plus both drop-ins"
undrop

# A policy scalar replaces, and the later file in lexical order wins.
drop 10-a.toml '[secrets]
refresh_interval_sec = 11'
drop 20-b.toml '[secrets]
refresh_interval_sec = 22'
drop 30-c.toml '[exec.base_env]
MY_VAR = "set-by-a-drop-in"'
# The exit code alone will not say: --check fails for a short ref on this host
# too, so the question is whether anything was refused about THIS key.
if why | grep -qi 'refresh_interval_sec'; then
  bad "two drop-ins setting one scalar was refused: $(why | grep -i refresh_interval_sec | head -1 | cut -c1-90)"
else
  ok "a scalar set twice is not an error: the later file replaces"
fi
settle || bad "the host did not come back"
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 -C /home/op/project -- /bin/sh -c 'echo $MY_VAR' 2>&1)
[ "$(tail -1 <<<"$out")" = "set-by-a-drop-in" ] \
  && ok "and a table merges key by key: the drop-in's base_env variable reaches a command" \
  || bad "the drop-in's [exec.base_env] did not reach the child: ${out:0:90}"
# Merged, not replaced: PATH from the base is still there, or nothing would run.
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 -C /home/op/project -- /bin/sh -c 'echo $PATH' 2>&1)
grep -q '/usr/bin' <<<"$out" && ok "while the base's PATH survived the merge" \
  || bad "the drop-in replaced [exec.base_env] wholesale: ${out:0:90}"
undrop; settle || bad "the host did not come back"

# A list that is policy rather than an inventory has one owner.
drop 10-a.toml '[secrets]
decrypt_command = ["/usr/local/bin/sops", "-d", "{file}"]'
drop 20-b.toml '[secrets]
decrypt_command = ["/bin/cat", "{file}"]'
out=$(why)
grep -qiE 'one owner|both|policy' <<<"$out" \
  && ok "a policy list set by two sources is refused, not merged" \
  || bad "two drop-ins set decrypt_command and neither was refused: $(grep -i error <<<"$out" | head -1 | cut -c1-90)"
undrop

# --------------------------------------------------------------------------
head_ "4. a drop-in that is wrong does not take the host down"

# The running broker holds its value set; a bad file must not be loaded into it.
refs_before=$(runuser -u op -- /usr/local/bin/faramir list-secrets 2>/dev/null | wc -l)
drop 90-broken.toml 'this is not toml [[['
why >/tmp/c4.log 2>&1
grep -qiE 'error|parse|cannot|expected|toml' /tmp/c4.log && ok "--check refuses a drop-in that will not parse" \
  || bad "a malformed drop-in was accepted"
# The running daemons have not been asked to reload, so they keep serving.
refs=$(runuser -u op -- /usr/local/bin/faramir list-secrets 2>/dev/null | wc -l)
[ "$refs" -eq "$refs_before" ] && ok "and the running broker keeps serving until it is reloaded" \
  || bad "a file on disk changed what a running broker serves ($refs_before -> $refs)"

# Now reload into it, which is the operator's mistake this has to survive.
# Reload stops the services and starts the sockets; it never reads the config,
# so a file the daemons cannot load is found by the first command that needs
# them, on a socket systemd is already listening on.
/usr/local/bin/faramir reload >/tmp/c4-reload.log 2>&1; code=$?
if [ $code -ne 0 ]; then
  ok "reload onto a broken config fails loudly (exit $code)"
else
  bad "reload onto a config the daemons cannot load reported success (exit 0)"
fi
grep -qi 'does not load' /tmp/c4-reload.log \
  && ok "and says which file and which account could not load it" \
  || bad "the refusal does not name the file: $(head -c 90 /tmp/c4-reload.log)"
# Nothing was stopped, so the daemons keep serving what they already had.
timeout 20 runuser -u op -- /usr/local/bin/faramir list-secrets >/tmp/c4-agent.log 2>&1
agent=$?
case $agent in
  124) bad "the agent hangs after a refused reload (killed at 20s; broker.service=$(systemctl is-active faramir-broker.service))";;
  0)   ok "and the agent is still served by the configuration already loaded";;
  *)   bad "the agent cannot work after a refused reload (exit $agent)";;
esac
undrop
settle || bad "the host did not recover after the broken drop-in was removed"
refs=$(runuser -u op -- /usr/local/bin/faramir list-secrets 2>/dev/null | wc -l)
[ "$refs" -eq "$refs_before" ] && ok "and removing the drop-in restores what it served" \
  || bad "after recovery the broker serves $refs of $refs_before refs"

# --------------------------------------------------------------------------
head_ "5. reload itself"

out=$(runuser -u op -- /usr/local/bin/faramir reload 2>&1); code=$?
[ $code -ne 0 ] && grep -qi 'root' <<<"$out" && ok "reload as the agent's uid is refused: it stops the units" \
  || bad "reload as op: exit $code ${out:0:90}"

# Repeatable, which is what an operator fixing a config does.
fine=yes
for _ in $(seq 4); do
  /usr/local/bin/faramir reload >/dev/null 2>&1 || fine=no
done
[ "$fine" = yes ] && ok "four reloads in a row all succeed" || bad "a repeated reload failed"
for u in faramir-keeper.socket faramir-exec.socket faramir-broker.socket; do
  [ "$(systemctl is-active $u)" = active ] || bad "$u is $(systemctl is-active $u) after repeated reloads"
done
ok "and every socket is still listening"
settle || bad "the host did not settle"

# --------------------------------------------------------------------------
head_ "6. init rewrites its own file and leaves a drop-in alone"

drop 40-mine.toml '[secrets]
refresh_interval_sec = 9'
sum_before=$(sha256sum $DROPIN/40-mine.toml | cut -d" " -f1)
# A hand edit to the base, which init owns and replaces without warning.
printf '\n# an operator edit that init will discard\n' >> $CFG
/usr/local/bin/faramir init --operator-user op >/tmp/c6.log 2>&1
grep -q 'an operator edit' $CFG && bad "init kept a hand edit to its own file" \
  || ok "init rewrote config.toml, discarding the hand edit"
[ "$(sha256sum $DROPIN/40-mine.toml | cut -d' ' -f1)" = "$sum_before" ] \
  && ok "and left the drop-in byte-identical" || bad "init rewrote the operator's drop-in"
undrop
settle || bad "the host did not settle after init"

# --------------------------------------------------------------------------
head_ "7. and none of this leaked a value"

grep -rqF "$SECRET" $DROPIN /tmp/c1.json /tmp/c4.log 2>/dev/null \
  && bad "a value is in the configuration or in a --check report" \
  || ok "no value in the drop-ins or in what --check reported"
grep -qF "$SECRET" /var/log/faramir/audit.log && bad "a value reached the audit log" \
  || ok "and none in the audit log"

# --------------------------------------------------------------------------
summary

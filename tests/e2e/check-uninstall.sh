#!/bin/bash
# `faramir uninstall`, and what it is right to leave behind.
#
# It removes the broker and keeps the age key, the secrets, the config and the
# log: deleting the key would make every managed sops file unreadable, and no
# re-install brings that back. So half of this suite is about what SURVIVES.
#
# The other half is what must not: a host that was granted sudo has a sudoers
# entry and a PAM service naming a helper, and leaving either behind is a grant
# with nothing left to answer it.
#
# Destructive by design. Run last, on a container that can be thrown away.
set -u
CFGDIR=/etc/faramir
KEY=$CFGDIR/age.key
SECRETS=$CFGDIR/secrets/app.sops.yml
LOG=/var/log/faramir/audit.log
PROJECT=/home/op/project
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

gone()   { [ -e "$1" ] && bad "$2 survived: $1" || ok "$2 is gone"; }
kept()   { [ -e "$1" ] && ok "$2 is kept" || bad "$2 was removed: $1"; }

# The grant is what makes the interesting half of this suite exist.
if ! grep -q '^\[sudo\]' $CFGDIR/config.toml; then
  faramir init --allow-sudo --agent-user op >/tmp/u-init.log 2>&1 \
    || { echo "could not install the grant"; tail -3 /tmp/u-init.log; exit 1; }
  systemctl restart faramir-keeper.socket faramir-exec.socket faramir-broker.socket >/dev/null 2>&1
  waitfor 15 runuser -u op -- /usr/local/bin/faramir refs
fi

# A record to keep: an empty log satisfies "still there" without saying
# anything, and the log is one of the three things this command must not lose.
runuser -u op -- faramir run --quiet -t 20 -C $PROJECT -- /bin/echo before-uninstall >/dev/null 2>&1
cp /usr/local/bin/faramir /tmp/faramir.kept
key_sum=$(sha256sum $KEY | cut -d' ' -f1)
sec_sum=$(sha256sum $SECRETS | cut -d' ' -f1)
log_lines=$(wc -l <$LOG)
[ "$log_lines" -gt 0 ] || { echo "the log is empty, so U2 would prove nothing"; exit 1; }
refs_before=$(runuser -u op -- faramir refs 2>/dev/null | wc -l)
echo "before: $refs_before ref(s), $log_lines log line(s), grant installed"

# --------------------------------------------------------------------------
head_ "1. it stops what is running, before it removes it"

out=$(faramir uninstall 2>&1); code=$?
[ $code -eq 0 ] && ok "uninstall exits 0" || bad "uninstall exit $code: $(head -c 200 <<<"$out")"
for u in faramir-broker faramir-keeper faramir-exec; do
  state=$(systemctl is-active $u.service 2>/dev/null)
  [ "$state" = active ] && bad "$u.service is still running" || ok "$u.service is $state"
done
[ -S /run/faramir/broker.sock ] && bad "the broker socket is still there" || ok "no socket is left listening"
# No process of any of the three accounts survives the removal.
strays=""
for acct in faramir-broker faramir-keeper faramir-exec; do
  pids=$(pgrep -u $acct 2>/dev/null | tr '\n' ' ')
  [ -n "$pids" ] && strays="$strays $acct:$pids"
done
[ -z "$strays" ] && ok "and no daemon process is left behind" || bad "processes survived:$strays"

# --------------------------------------------------------------------------
head_ "2. what cannot be recreated is kept"

[ "$(sha256sum $KEY 2>/dev/null | cut -d' ' -f1)" = "$key_sum" ] \
  && ok "the age key is byte-identical" || bad "the age key was changed or removed"
[ "$(sha256sum $SECRETS 2>/dev/null | cut -d' ' -f1)" = "$sec_sum" ] \
  && ok "the ciphertext is byte-identical" || bad "the managed sops file was changed or removed"
kept $CFGDIR/config.toml "the config"
kept $CFGDIR/.sops.yaml "the creation rule"
kept $CFGDIR/id_ed25519 "the broker's ssh key"
[ -f $LOG ] && [ "$(wc -l <$LOG)" -ge "$log_lines" ] \
  && ok "the audit log is kept, $(wc -l <$LOG) line(s)" || bad "the audit log was removed or truncated"
# And it says so rather than leaving the operator to find out.
grep -q 'age.key' <<<"$out" && ok "and it names what it left behind" || bad "it does not say what it kept"

# The accounts stay, because the files they own do.
for acct in faramir-broker faramir-keeper faramir-exec; do
  id $acct >/dev/null 2>&1 && ok "the $acct account is kept" || bad "$acct was deleted, orphaning its files"
done
[ "$(stat -c %U $KEY)" = faramir-keeper ] && ok "and the key is still owned by a real account" \
  || bad "the key is owned by $(stat -c %U $KEY)"

# --------------------------------------------------------------------------
head_ "3. the sudo grant goes, all of it"
#
# The sudoers entry names the executor's uid and authenticates through a PAM
# service that execs a helper. With the broker gone nothing answers that
# question, so an entry left behind is a grant with no arrangement around it.

gone /etc/sudoers.d/faramir "the sudoers entry"
gone /etc/pam.d/faramir-sudo "the PAM service"
gone /usr/local/libexec/faramir "the libexec directory, helper included"
# Uninstall leaves the accounts, which is what makes the three above matter: a
# leftover sudoers entry would name a uid that still exists and still be live.
id faramir-exec >/dev/null 2>&1 \
  && ok "the account it named is still here, which is why removing them matters" \
  || bad "faramir-exec is gone, so uninstall removed an account it reports keeping"
# Nothing anywhere else grants it either.
if sudo -l -U faramir-exec 2>/dev/null | grep -qiE 'may run|NOPASSWD'; then
  bad "faramir-exec still holds a sudo grant from somewhere: $(sudo -l -U faramir-exec 2>/dev/null | tail -2 | tr '\n' ' ')"
else
  ok "and faramir-exec holds no sudo grant from any source"
fi

# --------------------------------------------------------------------------
head_ "4. the rest of the install"

gone /etc/systemd/system/faramir-broker.service "the broker unit"
gone /etc/systemd/system/faramir-keeper.socket "the keeper socket unit"
gone /etc/tmpfiles.d/faramir.conf "the tmpfiles rule"
gone /etc/logrotate.d/faramir "the rotation rule"
gone /run/faramir "the runtime directory"
gone /usr/local/share/doc/faramir "the doc directory"
gone /usr/local/bin/faramir "the binary"
# systemd is left with no dangling units.
systemctl list-unit-files 'faramir-*' 2>/dev/null | grep -q faramir \
  && bad "systemd still lists faramir units" || ok "systemd lists no faramir unit"

# --------------------------------------------------------------------------
head_ "5. an enrolled working tree"
#
# init-project shares a tree with the executor. Uninstall does not walk the
# operator's directories, so what it leaves is worth stating: the grant on the
# tree outlives the broker, and the account it names still exists.

if [ -d $PROJECT ]; then
  # Shared by setgid group ownership rather than by an ACL, so that is what is
  # left behind: the tree stays open to the client group, and every account in
  # it still exists because uninstall keeps the accounts.
  owner=$(stat -c '%a %U:%G' $PROJECT)
  [ "$owner" = "2770 op:faramir-client" ] && ok "the enrolled tree is still $owner, which uninstall does not walk" \
    || bad "the tree is $owner, want 2770 op:faramir-client"
  getent group faramir-client >/dev/null && ok "and the group it is shared with still exists" \
    || bad "the client group was removed, orphaning the tree's group"
  id -nG faramir-exec 2>/dev/null | grep -qw dev \
    && note "so faramir-exec, which is kept, can still enter it" \
    || note "and faramir-exec is not in that group"
  # The agent's own config, which now names a binary that is gone.
  f=.claude/settings.local.json
  [ -e "$PROJECT/$f" ] && ok "  $f is left, naming a broker that is not there" \
    || bad "  $f was removed from the operator's tree"
else
  bad "no enrolled tree to examine"
fi

# --------------------------------------------------------------------------
head_ "6. running it again"

install -m0755 /tmp/faramir.kept /usr/local/bin/faramir
out=$(faramir uninstall 2>&1); code=$?
[ $code -eq 0 ] && ok "a second uninstall is not an error" \
  || bad "second uninstall exit $code: $(head -c 150 <<<"$out")"
[ "$(sha256sum $KEY | cut -d' ' -f1)" = "$key_sum" ] && ok "and still keeps the key" \
  || bad "the second run touched the key"

# --------------------------------------------------------------------------
head_ "7. and the host can be rebuilt from what was kept"

install -m0755 /tmp/faramir.kept /usr/local/bin/faramir
if faramir init --agent-user op >/tmp/reinit.log 2>&1; then
  ok "init runs again on the uninstalled host"
else
  bad "re-init failed: $(tail -3 /tmp/reinit.log)"
fi
[ "$(sha256sum $KEY | cut -d' ' -f1)" = "$key_sum" ] \
  && ok "it did not mint a second age key over the first" \
  || bad "re-init replaced the age key, so every managed file is now unreadable"
[ "$(sha256sum $SECRETS | cut -d' ' -f1)" = "$sec_sum" ] \
  && ok "and left the ciphertext alone" || bad "re-init rewrote the ciphertext"

for _ in $(seq 25); do
  refs=$(runuser -u op -- faramir refs 2>/dev/null | wc -l)
  [ "$refs" -ge "$refs_before" ] && break
  sleep 1
done
[ "$refs" -ge "$refs_before" ] && ok "the same $refs ref(s) load again" \
  || bad "only $refs of $refs_before refs came back"
out=$(runuser -u op -- faramir run --quiet -t 20 -C $PROJECT \
  --env PW=faramir://db/password -- /bin/sh -c 'echo $PW' 2>&1)
grep -q '«SECRET:db/password»' <<<"$out" && ok "and a brokered command still gets a value, redacted" \
  || bad "a brokered command after the round trip: ${out:0:110}"
# The grant does not come back on its own: it is --allow-sudo's, per install.
[ -e /etc/sudoers.d/faramir ] && bad "a plain init restored the sudo grant" \
  || ok "and a plain init does not restore the sudo grant"

# --------------------------------------------------------------------------
head_ "8. and from an archive, onto a host with nothing left of the install"
# The documented backup: the config directory, holding the key, the rule and the
# ciphertext together. Section 7 rebuilds from what uninstall KEPT in place;
# this removes all of it, accounts included, and restores from the archive, which
# is the procedure an operator follows when the host itself is gone.
tar czf /tmp/faramir-backup.tgz -C / etc/faramir 2>/dev/null \
  && ok "the config directory archives" || bad "could not archive /etc/faramir"

faramir uninstall >/dev/null 2>&1
rm -rf /etc/faramir
for account in faramir-keeper faramir-broker faramir-exec; do
  userdel "$account" >/dev/null 2>&1
done
groupdel faramir-keeper >/dev/null 2>&1
[ -e /etc/faramir ] && bad "the config directory survived the wipe" || ok "the install is gone"
getent passwd faramir-keeper >/dev/null && bad "the keeper account survived" \
  || ok "and so are the accounts"

tar xzf /tmp/faramir-backup.tgz -C /
install -m0755 /tmp/faramir.kept /usr/local/bin/faramir
faramir init --agent-user op >/tmp/restore.log 2>&1 \
  && ok "init runs against the restored directory" \
  || bad "restore failed: $(tail -3 /tmp/restore.log)"
# Adopted, not minted: a run that replaced the key would leave every restored
# file unreadable, which is the one outcome a restore cannot survive.
grep -qE '^ok +age key' /tmp/restore.log \
  && ok "it adopted the key in the archive rather than minting one" \
  || bad "init did not adopt the restored key: $(grep -i 'age key' /tmp/restore.log)"
grep -qE '^ok +sops config: keeping' /tmp/restore.log \
  && ok "and kept the creation rule that came with it" \
  || bad "init did not keep the restored rule: $(grep -i 'sops config' /tmp/restore.log)"
[ "$(sha256sum $SECRETS | cut -d' ' -f1)" = "$sec_sum" ] \
  && ok "and nothing was re-encrypted" || bad "the restore rewrote the ciphertext"

for _ in $(seq 25); do
  refs=$(runuser -u op -- faramir refs 2>/dev/null | wc -l)
  [ "$refs" -ge "$refs_before" ] && break
  sleep 1
done
[ "$refs" -ge "$refs_before" ] && ok "the store opens again, $refs ref(s)" \
  || bad "only $refs of $refs_before refs came back from the archive"

# --------------------------------------------------------------------------
summary

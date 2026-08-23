#!/bin/bash
# Functional test of the secret lifecycle: edit, reseal, and what happens when the
# age key stops matching the ciphertext.
#
# The stakes are why this is worth a suite of its own. Every other mistake here
# is recoverable by re-running something; re-encrypting to a recipient set that
# leaves the keeper out is not, and neither is losing the key. So the tests are
# as much about what the tool REFUSES as about what it does.
#
# Sections 8 to 13 are the .sops.yaml a reader would not think to write: a rule
# taken from a directory that is not this install's, and shapes sops reads
# differently from how they look. Each is a way the store ends up sealed to the
# wrong people, or written in the clear, with every command reporting success --
# which is why they are put to a real install rather than to a parser.
set -u
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

MANAGED=/etc/faramir/secrets/app.sops.yml
LOG=/var/log/faramir/audit.log
sum() { sha256sum "$MANAGED" | cut -c1-16; }
brokered() { runuser -u op -- faramir run --quiet -t 25 "$@" 2>&1; }
# reload the daemons onto a changed store. reset-failed first and a settle
# after: a socket unit carries systemd's default start limit (5 starts / 10s),
# and this suite restarts them once per group, so without this the last group
# measures a host the earlier ones rate-limited into `failed`.
reload_daemons() {
  systemctl reset-failed faramir-keeper.socket faramir-keeper.service \
    faramir-broker.socket faramir-broker.service faramir-exec.socket >/dev/null 2>&1
  systemctl restart faramir-keeper.socket faramir-broker.socket >/dev/null 2>&1
  for _ in $(seq 20); do
    runuser -u op -- faramir refs >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# This suite rotates db/password, adds a ref, and rewrites .sops.yaml. Those
# values are shared: leak, stream, wrap, mcp and disclose all redact the
# original db/password, so a suite that leaves it rotated makes those fail when
# they run next against the same box. Snapshot the store and rule now, restore
# them on the way out, and reload the daemons onto the restored file, so running
# this suite composes with the others rather than sabotaging them. The exit
# status the counts imply is preserved across the restore.
BACKUP=$(mktemp -d)
cp -a "$MANAGED" "$BACKUP/store" 2>/dev/null || true
cp -a /etc/faramir/.sops.yaml "$BACKUP/sops" 2>/dev/null || true
restore_baseline() {
  local rc=$?
  [ -e "$BACKUP/store" ] && cp -a "$BACKUP/store" "$MANAGED"
  [ -e "$BACKUP/sops" ] && cp -a "$BACKUP/sops" /etc/faramir/.sops.yaml
  rm -rf "$BACKUP"
  reload_daemons >/dev/null 2>&1 || true
  return "$rc"
}
trap restore_baseline EXIT

# --------------------------------------------------------------------------
head_ "1. edit: the plaintext exists only in a tmpfs, 0600, and is removed"
# The editor is where a person would be. It records what it was handed, so the
# assertions below are about the file the operator's editor actually opens.
cat > /usr/local/sbin/spy-editor <<'EOF'
#!/bin/bash
target="$1"
{
  echo "path=$target"
  echo "mode=$(stat -c %a "$target")"
  echo "owner=$(stat -c %U:%G "$target")"
  echo "fstype=$(stat -fc %T "$(dirname "$target")")"
  echo "plaintext=$(grep -c 'hunter2-correct-horse-battery' "$target")"
} > /tmp/spy.out
# And the edit itself: a new value for db/password, plus a new ref.
cat > "$target" <<'YAML'
db:
  password: rotated-by-the-editor-9999
api:
  token: tok_live_ORIGINAL_0001
new:
  ref: added-in-the-editor-4242
YAML
EOF
chmod 0755 /usr/local/sbin/spy-editor

before=$(sum)
if faramir vault edit --editor /usr/local/sbin/spy-editor "$MANAGED" >/tmp/edit.log 2>&1; then
  ok "edit completed"
else
  bad "edit failed: $(tail -2 /tmp/edit.log)"
fi
# shellcheck disable=SC1091  # written by the editor this suite installs, at run time
. /tmp/spy.out 2>/dev/null || true
# shellcheck disable=SC2154  # path, mode, owner and fstype come from the editor, through /tmp/spy.out
[ "${fstype:-}" = "tmpfs" ] && ok "the editor was handed a file on tmpfs (${path%/*})" \
  || bad "the plaintext was on ${fstype:-unknown}, not a tmpfs: ${path:-?}"
[ "${mode:-}" = "600" ] && ok "it was 0600 (${owner:-?})" || bad "it was mode ${mode:-?}, want 600"
[ "${plaintext:-0}" = "1" ] && ok "the editor saw the decrypted value" \
  || bad "the editor was handed something that was not the plaintext"
[ -e "${path:-/nonexistent}" ] && bad "the plaintext file survived the edit: $path" \
  || ok "the plaintext file is gone after the edit"
# Nothing decrypted is left lying around in the tmpfs either.
if [ -z "$(find /dev/shm -name 'faramir-edit-*' 2>/dev/null)" ]; then
  ok "no faramir-edit-* directory left in /dev/shm"
else
  bad "an edit directory survived: $(find /dev/shm -name 'faramir-edit-*')"
fi

head_ "2. what landed on disk is still ciphertext"
[ "$(sum)" != "$before" ] && ok "the managed file changed" || bad "the file was not rewritten"
[ "$(grep -c 'rotated-by-the-editor-9999' "$MANAGED")" -eq 0 ] \
  && ok "the new value is not in the file in plaintext" \
  || bad "PLAINTEXT ON DISK: the edited value is readable in $MANAGED"
[ "$(grep -c 'ENC\[' "$MANAGED")" -ge 3 ] && ok "$(grep -c 'ENC\[' "$MANAGED") values are sops-encrypted" \
  || bad "the file does not look encrypted"
[ "$(stat -c '%a %U:%G' "$MANAGED")" = "640 root:faramir-keeper" ] \
  && ok "ownership and mode survived the edit (0640 root:faramir-keeper)" \
  || bad "the edit changed ownership: $(stat -c '%a %U:%G' "$MANAGED")"

head_ "3. the running broker picks the change up with no restart"
# [secret] min_refresh_sec bounds how often the broker may ask the keeper
# whether a file changed, so the pickup is on the first request after that
# window rather than on the next request. Polled to the interval plus slack,
# which is the claim: no restart, not instantaneous.
interval=$(grep -oP 'min_refresh_sec = \K[0-9]+' /etc/faramir/config.toml)
took=""
for i in $(seq $(( interval + 10 )) ); do
  refs=$(runuser -u op -- faramir refs 2>/dev/null | tr '\n' ' ')
  case "$refs" in *new/ref*) took=$i; break;; esac
  sleep 1
done
[ -n "$took" ] && ok "the ref added in the editor is served after ${took}s, no restart (interval ${interval}s)" \
  || bad "the new ref is not being served within $(( interval + 10 ))s: $refs"
out=$(brokered --env V=faramir://new/ref -- /bin/sh -c 'echo GOT=$V')
echo "$out" | grep -q 'GOT=«SECRET:new/ref»' && ok "it injects and comes back as its token" \
  || bad "injection of the new ref: $out"
# The value the editor replaced must no longer be redacted, and the new one must
# be: that is the redactor having been rebuilt from the current file.
out=$(brokered -- /bin/sh -c 'echo A-rotated-by-the-editor-9999-B')
echo "$out" | grep -q '«SECRET:db/password»' && ok "the NEW value is redacted in output" \
  || bad "the new value was printed unredacted: $out"
out=$(brokered -- /bin/sh -c 'echo A-hunter2-correct-horse-battery-B')
echo "$out" | grep -q 'hunter2' && ok "the replaced value is no longer in the set (printed as-is)" \
  || bad "the old value is still being redacted, so the set is stale: $out"

# --------------------------------------------------------------------------
head_ "4. reseal --dry-run writes nothing"
KEEPER=$(age-keygen -y /etc/faramir/age.key 2>/dev/null)
SECOND=$(age-keygen 2>/dev/null | tee /tmp/second.key | grep -o 'age1[a-z0-9]*' | head -1)
[ -n "$KEEPER" ] && ok "the keeper's recipient: ${KEEPER:0:20}..." || bad "could not read the keeper's public half"
cat > /etc/faramir/.sops.yaml <<YAML
creation_rules:
  - path_regex: \.sops\.ya?ml\$
    key_groups:
      - age:
          - $KEEPER
          - $SECOND
YAML
before=$(sum)
faramir reader reseal --dry-run >/tmp/dry.log 2>&1
[ "$(sum)" = "$before" ] && ok "the file is byte-identical after a dry run" \
  || bad "a dry run rewrote the file"
grep -qiE "would|dry" /tmp/dry.log && ok "it reported what it would do: $(grep -iE 'would|dry' /tmp/dry.log | head -1 | cut -c1-70)" \
  || bad "a dry run said nothing useful: $(head -2 /tmp/dry.log)"

head_ "5. reseal to a second recipient, and the keeper can still read"
faramir reader reseal >/tmp/reseal.log 2>&1 && ok "reseal completed" || bad "reseal failed: $(tail -2 /tmp/reseal.log)"
[ "$(sum)" != "$before" ] && ok "the file was re-encrypted" || bad "the file did not change"
if grep -q "$SECOND" "$MANAGED"; then ok "the second recipient is now in the file's metadata"; else
  bad "the new recipient is not in the file"; fi
reload_daemons || bad "the daemons did not come back"
refs=$(runuser -u op -- faramir refs 2>&1 | tr '\n' ' ')
echo "$refs" | grep -q "faramir://new/ref" && ok "the keeper still decrypts everything after the reseal" \
  || bad "the keeper cannot read the re-encrypted file: $refs"

head_ "6. THE REFUSAL: a rule that drops the keeper's own key"
cat > /etc/faramir/.sops.yaml <<YAML
creation_rules:
  - path_regex: \.sops\.ya?ml\$
    key_groups:
      - age:
          - $SECOND
YAML
before=$(sum)
if faramir reader reseal >/tmp/bad-reseal.log 2>&1; then
  bad "re-encrypting to a set without the keeper's key SUCCEEDED, which is unrecoverable"
else
  ok "refused: $(grep -oE 'does not list|would leave' /tmp/bad-reseal.log | head -1)"
fi
[ "$(sum)" = "$before" ] && ok "and the file is byte-identical, so nothing was half-written" \
  || bad "the refused reseal still modified the file"
# The proof that the refusal saved something: the keeper still reads it.
reload_daemons || bad "the daemons did not come back"
runuser -u op -- faramir refs 2>&1 | grep -q "faramir://new/ref" \
  && ok "the secrets still decrypt after the refusal" || bad "the refusal left the secrets unreadable"

head_ "7. an edit preserves who can read the file, whatever .sops.yaml now says"
# reseal applies a changed rule; edit must not, or editing a value would quietly
# reseal the file to whoever the rule names today.
cat > /etc/faramir/.sops.yaml <<YAML
creation_rules:
  - path_regex: \.sops\.ya?ml\$
    key_groups:
      - age:
          - $SECOND
YAML
was=$(grep -c 'recipient:' "$MANAGED")
cat > /usr/local/sbin/spy-editor <<'EOF'
#!/bin/bash
sed -i 's/rotated-by-the-editor-9999/edited-again-under-a-changed-rule/' "$1"
EOF
chmod 0755 /usr/local/sbin/spy-editor
if faramir vault edit --editor /usr/local/sbin/spy-editor "$MANAGED" >/tmp/edit2.log 2>&1; then
  ok "the edit went through with a rule naming somebody else"
else
  bad "edit failed: $(tail -2 /tmp/edit2.log)"
fi
now=$(grep -c 'recipient:' "$MANAGED")
[ "$was" = "$now" ] && ok "the recipient count is unchanged ($now), so the rule was not applied" \
  || bad "the edit changed the recipient set: $was -> $now"
grep -q "$KEEPER" "$MANAGED" && ok "the keeper is still a recipient after editing under a hostile rule" \
  || bad "UNRECOVERABLE: the edit sealed the file away from the keeper"
reload_daemons || bad "the daemons did not come back"
runuser -u op -- faramir refs 2>&1 | grep -q "faramir://new/ref" \
  && ok "and the broker still decrypts it" || bad "the file is no longer readable"

# Two edits of one file each decrypt their own copy, so whichever encrypts last
# would replace the other's work with a copy that never had it -- both reporting
# the file written, and a secret just saved gone with nothing said.
cat > /usr/local/sbin/slow-editor <<'EOF'
#!/bin/bash
sleep 3
printf 'raced: aaaaaaaaaaaa
' >> "$1"
EOF
cat > /usr/local/sbin/quick-editor <<'EOF'
#!/bin/bash
printf 'wonrace: bbbbbbbbbbbb
' >> "$1"
EOF
chmod 0755 /usr/local/sbin/slow-editor /usr/local/sbin/quick-editor
( faramir vault edit --editor /usr/local/sbin/slow-editor "$MANAGED" >/tmp/edit-slow.log 2>&1
  echo $? > /tmp/edit-slow.rc ) &
sleep 1
faramir vault edit --editor /usr/local/sbin/quick-editor "$MANAGED" >/tmp/edit-quick.log 2>&1
echo $? > /tmp/edit-quick.rc
wait
slow=$(cat /tmp/edit-slow.rc); quick=$(cat /tmp/edit-quick.rc)
[ "$slow" = 0 ] && [ "$quick" = 0 ] \
  && bad "both concurrent edits reported success, so one was lost silently" \
  || ok "concurrent edits do not both report success (slow=$slow quick=$quick)"
# Whichever was refused says why, and the file is one of the two edits rather
# than a mix or a truncation.
cat /tmp/edit-slow.log /tmp/edit-quick.log | grep -qE "changed while this was working on it|was not saved" \
  && ok "  and the one that lost says the file moved under it" \
  || bad "  neither refusal explains itself: $(tail -1 /tmp/edit-slow.log)"
reload_daemons || bad "the daemons did not come back"
runuser -u op -- faramir refs 2>&1 | grep -q "faramir://new/ref" \
  && ok "  and the store still decrypts afterwards" || bad "  the store is unreadable after the race"
rm -f /usr/local/sbin/slow-editor /usr/local/sbin/quick-editor \
  /tmp/edit-slow.log /tmp/edit-quick.log /tmp/edit-slow.rc /tmp/edit-quick.rc

# A value at or over the kernel's cap on one environment variable. It could
# never be injected -- `run` fails it with the exec's own "argument list too
# long" -- and holding one is not free: the value set costs about 19 KB of
# memory per byte of secret, so a value this size takes the broker to several
# gigabytes and then to the OOM killer, at which point nothing is redacted.
python3 -c "open('/tmp/huge.yml','w').write('toobig: %s\n' % ('x' * 200000))"
faramir vault add --from /tmp/huge.yml e2e-toobig >/dev/null 2>&1
rm -f /tmp/huge.yml
reload_daemons || bad "the daemons did not come back after a huge value"
runuser -u op -- faramir refs 2>/dev/null | grep -q 'faramir://toobig' \
  && bad "a value too large to inject is served" \
  || ok "a value too large to inject is refused at load"
pid=$(systemctl show -p MainPID --value faramir-broker.service)
rss=$(awk '/VmRSS/{print $2}' /proc/"$pid"/status 2>/dev/null)
[ -n "$rss" ] && [ "$rss" -lt 1000000 ] \
  && ok "  and the broker is ${rss}kB rather than gigabytes" \
  || bad "  the broker is ${rss:-gone}kB with one oversized value in the store"
out=$(runuser -u op -- /usr/local/bin/faramir run --quiet -t 20 \
  --env V=faramir://toobig -- /bin/true 2>&1)
[ -n "$out" ] && ok "  and asking for it is refused" \
  || bad "  asking for a value that was refused at load ran anyway"
faramir vault rm --force e2e-toobig >/dev/null 2>&1
reload_daemons || bad "the daemons did not come back"

# --------------------------------------------------------------------------
# The shapes below are the ones a reader would not think to try: a .sops.yaml
# written in a way an earlier version read differently from sops, and a rule
# taken from somewhere that is not this install. Each is a way the store gets
# sealed to the wrong people, or written in the clear, with every command
# reporting success.

# rule writes .sops.yaml from the creation rules on stdin, so the cases below
# differ only in the rule and not in the plumbing around them.
rule() { { printf 'creation_rules:\n'; cat; } > /etc/faramir/.sops.yaml; }

# editor installs a one-line editor that leaves a mark when it runs, so a test
# can assert an edit was refused BEFORE anything was typed rather than after.
editor() {
  printf '#!/bin/bash\ntouch /tmp/editor-ran\n%s\n' "$1" > /usr/local/sbin/spy-editor
  chmod 0755 /usr/local/sbin/spy-editor
  rm -f /tmp/editor-ran
}
ran() { [ -e /tmp/editor-ran ]; }
recipients() { grep -c 'recipient:' "$MANAGED"; }

head_ "8. a .sops.yaml where the command was RUN does not govern the edit"
# sops resolves creation rules by walking up from the working directory, and an
# operator runs `sudo faramir vault edit` from wherever they are standing, which on
# this host is an enrolled tree the agent writes. A rule found there deciding
# how the store is written is `unencrypted_regex` putting managed values on disk
# in the clear.
rule <<YAML
  - path_regex: \.sops\.ya?ml\$
    key_groups:
      - age:
          - $KEEPER
          - $SECOND
YAML
PLANTED=$(mktemp -d)
cat > "$PLANTED/.sops.yaml" <<YAML
creation_rules:
  - path_regex: .*
    unencrypted_regex: '^(password|token|ref)\$'
    key_groups:
      - age:
          - $SECOND
YAML
editor "sed -i 's/edited-again-under-a-changed-rule/planted-rule-must-not-expose-me/' \"\$1\""
if (cd "$PLANTED" && faramir vault edit --editor /usr/local/sbin/spy-editor "$MANAGED") \
    >/tmp/planted.log 2>&1; then
  ok "the edit completed from a directory carrying a .sops.yaml of its own"
else
  bad "edit failed: $(tail -2 /tmp/planted.log)"
fi
if grep -q 'planted-rule-must-not-expose-me' "$MANAGED"; then
  bad "PLAINTEXT ON DISK: a .sops.yaml in the working directory decided how the store was written"
else
  ok "the planted rule did not reach the encryption: the value is not in the file"
fi
rm -rf "$PLANTED"

head_ "9. reseal keeps a recipient named only under a merged key group"
# A key group may pull in others with `merge:`, and their keys seal the file
# exactly like the ones written inline. A reader that stops at the top level
# re-encrypts the store without them, which takes a backup key's access away for
# good: re-running does not give it back.
rule <<YAML
  - path_regex: \.sops\.ya?ml\$
    key_groups:
      - age:
          - $KEEPER
YAML
faramir reader reseal >/tmp/narrow.log 2>&1 || bad "narrowing to the keeper alone failed: $(tail -2 /tmp/narrow.log)"
[ "$(recipients)" -eq 1 ] && ok "narrowed to the keeper alone, so the merged rule has something to add" \
  || note "the store already had $(recipients) recipients before the merge case"
rule <<YAML
  - path_regex: \.sops\.ya?ml\$
    key_groups:
      - age:
          - $KEEPER
        merge:
          - age:
              - $SECOND
YAML
faramir reader reseal >/tmp/merge.log 2>&1 && ok "reseal completed under a merged key group" \
  || bad "reseal failed: $(tail -2 /tmp/merge.log)"
grep -q "$SECOND" "$MANAGED" \
  && ok "the recipient named only under merge: is in the file, so it can still read the store" \
  || bad "UNRECOVERABLE: reseal dropped the merged recipient, and re-running does not restore its access"
grep -q "$KEEPER" "$MANAGED" && ok "and so is the keeper's" || bad "the keeper was dropped"

head_ "10. a bare age: beside key_groups is the one sops ignores"
# sops reads a rule's `age` shorthand only where it has no key groups. Reading
# both names a reader the rule does not grant, and would let a check report the
# keeper as still listed on a rule that seals the file without it.
rule <<YAML
  - path_regex: \.sops\.ya?ml\$
    age: $SECOND
    key_groups:
      - age:
          - $KEEPER
YAML
faramir reader reseal >/tmp/shorthand.log 2>&1 && ok "reseal completed" \
  || bad "reseal failed: $(tail -2 /tmp/shorthand.log)"
[ "$(recipients)" -eq 1 ] && ok "the file names one recipient, which is what sops would have sealed it to" \
  || bad "the file names $(recipients) recipients, so the ignored shorthand was applied"
grep -q "$SECOND" "$MANAGED" \
  && bad "the store is readable by a key the rule does not actually grant" \
  || ok "the key named only in the ignored shorthand is not a reader"
reload_daemons || bad "the daemons did not come back"
runuser -u op -- faramir refs 2>&1 | grep -q "faramir://new/ref" \
  && ok "and the keeper still decrypts the store" || bad "the store is no longer readable"

head_ "11. THE REFUSAL: two creation rules, whatever order the keys are in"
# Which rule governs a file is a path_regex question this cannot answer, so it
# refuses rather than sealing half the store to a set that never governed it.
# Written with `age:` first, which is the spelling a reader anchored on
# path_regex counts as one rule.
rule <<YAML
  - age: $KEEPER
    path_regex: prod/.*\.sops\.ya?ml\$
  - age: $KEEPER,$SECOND
    path_regex: \.sops\.ya?ml\$
YAML
before=$(sum)
if faramir reader reseal >/tmp/tworule.log 2>&1; then
  bad "a two-rule .sops.yaml was accepted, so the store can be sealed to a set no rule names"
else
  ok "refused: $(grep -oE 'creation rules|updatekeys' /tmp/tworule.log | head -1)"
fi
[ "$(sum)" = "$before" ] && ok "and the file is byte-identical" || bad "the refused reseal wrote to the file"

head_ "12. THE REFUSAL: a rule that splits the data key"
# shamir_threshold means N key groups have to come together to open a file.
# Re-encrypting to one flat list of recipients turns that into any one of them,
# which is the protection removed by the command meant to preserve it.
rule <<YAML
  - path_regex: \.sops\.ya?ml\$
    shamir_threshold: 2
    key_groups:
      - age:
          - $KEEPER
      - age:
          - $SECOND
YAML
before=$(sum)
if faramir reader reseal >/tmp/shamir.log 2>&1; then
  bad "reseal flattened a split data key, so any single key now opens what took two"
else
  ok "reseal refused: $(grep -oE 'shamir_threshold' /tmp/shamir.log | head -1)"
fi
editor "sed -i 's/edited/edited/' \"\$1\""
if faramir vault edit --editor /usr/local/sbin/spy-editor "$MANAGED" >/tmp/shamir-edit.log 2>&1; then
  bad "edit wrote a split-key store back as one group, which removes the split silently"
else
  ok "edit refused it too: $(grep -oE 'shamir_threshold' /tmp/shamir-edit.log | head -1)"
fi
ran && bad "the editor ran before the refusal" || ok "and the editor never ran"
[ "$(sum)" = "$before" ] && ok "the store is byte-identical after both refusals" \
  || bad "a refused command still wrote to the file"

head_ "13. an edit no rule covers is refused before the editor opens"
# sops refuses a file no creation rule matches, and it refuses it at the encrypt,
# which is after the editor has exited. Learning then costs the operator
# everything they typed, so the question is put while there is nothing to lose.
rule <<YAML
  - path_regex: ^nowhere-near-the-store/.*\.sops\.yml\$
    key_groups:
      - age:
          - $KEEPER
YAML
before=$(sum)
editor "sed -i 's/edited/rewritten/' \"\$1\""
if faramir vault edit --editor /usr/local/sbin/spy-editor "$MANAGED" >/tmp/uncovered.log 2>&1; then
  bad "an edit went ahead under a rule that cannot write the file back"
else
  ok "refused: $(grep -oE 'no creation rule matching' /tmp/uncovered.log | head -1)"
fi
ran && bad "the editor ran first, so what was typed was discarded at the encrypt" \
  || ok "and the editor never ran, so nothing was typed and thrown away"
[ "$(sum)" = "$before" ] && ok "the store is untouched" || bad "the refused edit wrote to the file"
# What doctor says about the same host, which is where an operator would meet
# this before an edit does.
faramir doctor --agent-user op --json >/tmp/doc-cover.json 2>/dev/null
cover=$(jq -r '[.findings[]|select(.check=="rule coverage")|.status]|join(",")' /tmp/doc-cover.json)
[ "$cover" = failed ] && ok "doctor reports it under rule coverage before anybody edits" \
  || bad "doctor says rule coverage is [$cover] for a rule that reaches no managed file"

head_ "14. reader add and rm move the rule and the ciphertext together"
# What the two-step path left open: a rule naming a reader the existing files are
# not sealed to. Nothing fails there, so the test is that the state never exists
# rather than that a command reports it.
# Written with the installer's own comment, so the edit can be shown to keep it.
cat > /etc/faramir/.sops.yaml <<YAML
# Which files sops encrypts, and to whom.
creation_rules:
  - path_regex: \.sops\.ya?ml\$
    key_groups:
      - age:
          - $KEEPER
YAML
faramir reader reseal >/dev/null 2>&1 || bad "could not seal the store to the keeper alone"
grep -q "$SECOND" "$MANAGED" && bad "the store still names the second recipient" \
  || ok "the store starts sealed to the keeper alone"

before=$(sum)
faramir reader add --dry-run "$SECOND" >/tmp/add-dry.log 2>&1
[ "$(sum)" = "$before" ] && ok "a dry run leaves the ciphertext byte-identical" \
  || bad "a dry run re-encrypted the store"
grep -q "$SECOND" /etc/faramir/.sops.yaml && bad "a dry run wrote the rule" \
  || ok "and leaves the rule alone too"

faramir reader add "$SECOND" >/tmp/add.log 2>&1 \
  && ok "recipient add completed" || bad "recipient add failed: $(tail -2 /tmp/add.log)"
grep -q "$SECOND" /etc/faramir/.sops.yaml && ok "the rule names the new recipient" \
  || bad "the rule was not written"
grep -q "$SECOND" "$MANAGED" \
  && ok "and the ciphertext already agrees, with no second command" \
  || bad "the rule was written but the store was not re-encrypted"
grep -q '# Which files sops encrypts' /etc/faramir/.sops.yaml \
  && ok "the file's own comments survived the edit" \
  || bad "the edit rewrote the rule file from scratch"

# Twice is not an error and rewrites nothing: an operator who is unsure whether
# it took should be able to run it again.
before=$(sum)
faramir reader add "$SECOND" >/tmp/add2.log 2>&1 \
  && ok "adding one already there exits 0" || bad "a repeat add failed"
[ "$(sum)" = "$before" ] && ok "and re-encrypts nothing" || bad "a repeat add rewrote the store"

# THE RESUME: a rule that is already right over a store that is not. This is
# what a pass that wrote the rule and then failed on a file leaves behind, and
# an add that took the rule as proof would report success over it.
rule_now=$(cat /etc/faramir/.sops.yaml)
# Put the store back to the keeper alone while the rule still names both.
cat > /etc/faramir/.sops.yaml <<YAML
creation_rules:
  - path_regex: \.sops\.ya?ml\$
    key_groups:
      - age:
          - $KEEPER
YAML
faramir reader reseal >/dev/null 2>&1 || bad "could not stage the divergence"
printf '%s' "$rule_now" > /etc/faramir/.sops.yaml
grep -q "$SECOND" /etc/faramir/.sops.yaml || bad "staging lost the rule's second recipient"
grep -q "$SECOND" "$MANAGED" && bad "staging did not put the store back" \
  || ok "staged: the rule names the second recipient and the ciphertext does not"

faramir doctor --agent-user op --json >/tmp/doc-drift.json 2>/dev/null
drift=$(jq -r '[.findings[]|select(.check=="recipient drift")|.status]|join(",")' /tmp/doc-drift.json)
[ "$drift" = failed ] && ok "doctor reports it under recipient drift" \
  || bad "doctor says recipient drift is [$drift] for a store that lags its rule"

faramir reader add "$SECOND" >/tmp/resume.log 2>&1 \
  && ok "re-running the add over an unchanged rule exits 0" \
  || bad "the resume failed: $(tail -2 /tmp/resume.log)"
grep -q "$SECOND" "$MANAGED" \
  && ok "and it resealed the store the rule had run ahead of" \
  || bad "the rule was taken as proof and the store was left behind"
faramir doctor --agent-user op --json >/tmp/doc-drift2.json 2>/dev/null
[ "$(jq -r '[.findings[]|select(.check=="recipient drift")|.status]|join(",")' /tmp/doc-drift2.json)" = ok ] \
  && ok "and doctor reports no drift afterwards" || bad "doctor still reports drift"

# THE REFUSAL: the private half, where .sops.yaml is world-readable.
identity=$(grep -o 'AGE-SECRET-KEY-[A-Z0-9]*' /tmp/second.key | head -1)
if faramir reader add "$identity" >/tmp/identity.log 2>&1; then
  bad "an age IDENTITY was written into a 0644 rule file"
else
  ok "refused an identity where a recipient belongs: $(grep -oE 'private half' /tmp/identity.log | head -1)"
fi
grep -q 'AGE-SECRET-KEY' /etc/faramir/.sops.yaml && bad "the identity reached the rule file" \
  || ok "and nothing was written to the rule"

# THE REFUSAL: the keeper's own key, checked before the file is touched.
before=$(sum)
if faramir reader rm "$KEEPER" >/tmp/rm-keeper.log 2>&1; then
  bad "removed the key the keeper decrypts with, which is unrecoverable"
else
  ok "refused: $(grep -oE 'does not list|would leave' /tmp/rm-keeper.log | head -1)"
fi
grep -q "$KEEPER" /etc/faramir/.sops.yaml \
  && ok "and the rule still names the keeper, so nothing was half-written" \
  || bad "the refused removal edited the rule anyway"
[ "$(sum)" = "$before" ] && ok "and the ciphertext is untouched" || bad "the refused removal rewrote the store"

faramir reader rm "$SECOND" >/tmp/rm.log 2>&1 \
  && ok "recipient rm completed" || bad "recipient rm failed: $(tail -2 /tmp/rm.log)"
grep -q "$SECOND" "$MANAGED" && bad "the removed recipient is still in the ciphertext" \
  || ok "the ciphertext no longer names the removed recipient"

# The listing, and the one command here that needs no root.
runuser -u op -- faramir reader ls >/tmp/ls.log 2>&1 \
  && ok "recipients lists without root" || bad "recipients needed root: $(tail -2 /tmp/ls.log)"
grep -q "$KEEPER" /tmp/ls.log && ok "and names the keeper" || bad "the listing is missing the keeper"
# Which of two keys is this host's own is the question a listing raises, and
# answering it means reading the age key, which the agent's account cannot.
grep -q "keeper)" /tmp/ls.log && bad "the unprivileged listing claimed to know which key is the host's" \
  || ok "and does not claim to know which one is the host's"
faramir reader ls > /tmp/ls-root.log 2>&1
grep -qE "$KEEPER +\(this host" /tmp/ls-root.log \
  && ok "as root it marks the keeper's own key" \
  || bad "root's listing does not mark the keeper: $(cat /tmp/ls-root.log)"
grep -q "$SECOND" /tmp/ls.log && bad "the listing still names the removed recipient" \
  || ok "and not the one just removed"

# A host whose first secret has not been written yet. The rule governs what
# sops writes from then on, so a store with no files is not a reason to refuse.
mkdir -p /tmp/emptystore && mv /etc/faramir/secrets/*.sops.yml /tmp/emptystore/
if faramir reader add "$SECOND" >/tmp/empty.log 2>&1; then
  ok "recipient add works before the first secret exists"
else
  bad "recipient add refused a store with no files: $(tail -2 /tmp/empty.log)"
fi
faramir reader ls 2>/dev/null | grep -q "$SECOND" \
  && ok "and the rule was written" || bad "the rule was not written"
grep -q 'not reached' /tmp/empty.log \
  && bad "it reported each glob that matched nothing, which reads as three faults" \
  || ok "and said so once rather than once per pattern"
# reseal is the one whose job really is files, so it still refuses.
faramir reader reseal >/tmp/empty-reseal.log 2>&1 \
  && bad "reseal claimed success with no file to reseal" \
  || ok "reseal still refuses a store with no files"
mv /tmp/emptystore/*.sops.yml /etc/faramir/secrets/
faramir reader rm "$SECOND" >/dev/null 2>&1
faramir reader reseal >/dev/null 2>&1

# A dead end otherwise: this command edits the rule and cannot invent one.
mv /etc/faramir/.sops.yaml /tmp/rule.bak
faramir reader add "$SECOND" >/tmp/norule.log 2>&1 \
  && bad "added a recipient to a rule file that is not there" \
  || ok "refused with no .sops.yaml: $(grep -oE 'no such file' /tmp/norule.log | head -1)"
grep -q 'faramir init' /tmp/norule.log \
  && ok "and named what writes one" || bad "the refusal is a dead end: $(tail -1 /tmp/norule.log)"
mv /tmp/rule.bak /etc/faramir/.sops.yaml

# The store still opens, which is the only thing any of this is for.
reload_daemons || bad "the daemons did not come back"
runuser -u op -- faramir refs 2>&1 | grep -q "faramir://new/ref" \
  && ok "and the keeper still decrypts the store" || bad "the store is no longer readable"

head_ "15. add: the first managed file, without plaintext on a disk"
# What this replaces is sops with --config and --filename-override, which leaves
# the source cleartext on disk, writes 0644, and accepts a name the broker will
# never read. Each of those is asserted against here.
cat > /usr/local/sbin/writer <<'EOF'
#!/bin/bash
printf 'added:\n  by_the_editor: s3kr3t-added-4242\n' > "$1"
EOF
chmod 0755 /usr/local/sbin/writer

faramir vault add --editor /usr/local/sbin/writer added.sops.yml >/tmp/add.log 2>&1 \
  && ok "add completed" || bad "add failed: $(tail -2 /tmp/add.log)"
NEW=/etc/faramir/secrets/added.sops.yml
[ -e "$NEW" ] && ok "the file is there, named relative to the secrets directory" \
  || bad "no file at $NEW"
[ "$(stat -c '%a %U:%G' "$NEW")" = "640 root:faramir-keeper" ] \
  && ok "0640 root:faramir-keeper, like every other managed file" \
  || bad "a new file is $(stat -c '%a %U:%G' "$NEW"), not 640 root:faramir-keeper"
[ "$(grep -c 'ENC\[' "$NEW")" -ge 1 ] && ok "the value is encrypted" || bad "it is not encrypted"
grep -q 's3kr3t-added-4242' "$NEW" && bad "PLAINTEXT ON DISK in $NEW" \
  || ok "and the plaintext is not in it"
[ -z "$(find /dev/shm -name 'faramir-add-*' 2>/dev/null)" ] \
  && ok "no faramir-add-* directory left in /dev/shm" \
  || bad "a tmpfs directory survived: $(find /dev/shm -name 'faramir-add-*')"

reload_daemons || bad "the daemons did not come back"
runuser -u op -- faramir refs 2>&1 | grep -q 'faramir://added/by_the_editor' \
  && ok "and the broker serves the new ref" || bad "the new ref is not being served"

# THE REFUSAL: outside the secrets directory. A bare name gets the suffix, so
# what is left to refuse is a path the pattern cannot reach at all.
faramir vault add --editor /usr/local/sbin/writer /tmp/outside >/tmp/badname.log 2>&1 \
  && bad "created a file outside the secrets directory, which nothing would serve" \
  || ok "refused a path the pattern cannot reach: $(grep -oE 'matches none of' /tmp/badname.log | head -1)"
[ -e /tmp/outside.sops.yml ] && bad "and it wrote the file anyway" || ok "and wrote nothing"

# An existing file is edit's, and saying so is the whole of the message.
faramir vault add --editor /usr/local/sbin/writer added.sops.yml >/tmp/dup.log 2>&1 \
  && bad "overwrote a managed file" || ok "refused to overwrite one that is there"
grep -q 'vault edit' /tmp/dup.log && ok "and named the command that opens it" \
  || bad "the refusal does not say what to run instead"

# An editor that wrote nothing is somebody changing their mind.
printf '#!/bin/bash\ntrue\n' > /usr/local/sbin/empty-editor; chmod 0755 /usr/local/sbin/empty-editor
faramir vault add --editor /usr/local/sbin/empty-editor blank.sops.yml >/dev/null 2>&1 \
  && bad "created a managed file with nothing in it" || ok "an empty editor creates nothing"
[ -e /etc/faramir/secrets/blank.sops.yml ] && bad "and left the file behind" \
  || ok "and leaves no file behind"

# --from, and the one thing it has to say about the file it read.
printf 'svc:\n  token: tok-from-a-file\n' > /tmp/plain.yml
faramir vault add --from /tmp/plain.yml svc.sops.yml >/tmp/from.log 2>&1 \
  && ok "--from encrypts a file you already hold" || bad "--from failed: $(tail -2 /tmp/from.log)"
grep -q 'still cleartext' /tmp/from.log \
  && ok "and says the source is still cleartext" \
  || bad "it did not say the plaintext source survives"
grep -q 'tok-from-a-file' /etc/faramir/secrets/svc.sops.yml \
  && bad "PLAINTEXT ON DISK in the file it wrote" || ok "the file it wrote is ciphertext"

rm -f "$NEW" /etc/faramir/secrets/svc.sops.yml /tmp/plain.yml

head_ "16. a name is a name: the suffix is faramir's, not the operator's"
cat > /usr/local/sbin/writer3 <<'EOF'
#!/bin/bash
printf 'team:\n  key: a-long-enough-value\n' > "$1"
EOF
chmod 0755 /usr/local/sbin/writer3
faramir vault add --editor /usr/local/sbin/writer3 bare-name >/tmp/bare.log 2>&1 \
  && ok "add takes a name with no suffix" || bad "add failed: $(tail -2 /tmp/bare.log)"
[ -e /etc/faramir/secrets/bare-name.sops.yml ] \
  && ok "and writes bare-name.sops.yml" \
  || bad "no file at /etc/faramir/secrets/bare-name.sops.yml"
faramir vault edit --editor /usr/local/sbin/writer3 bare-name >/dev/null 2>&1 \
  && ok "edit takes the same short name" || bad "edit could not resolve the short name"
faramir vault ls 2>/dev/null | grep -qE '^bare-name ' \
  && ok "ls shows it without the suffix" || bad "ls does not show the short name"
faramir vault ls 2>/dev/null | head -1 | grep -q '^/etc/faramir/secrets$' \
  && ok "under the directory, named once so a full path is still readable off it" \
  || bad "the listing does not name the directory"
faramir vault ls --json 2>/dev/null | jq -e \
  '[.[]|select(.name=="bare-name")|.path]==["/etc/faramir/secrets/bare-name.sops.yml"]' >/dev/null \
  && ok "and --json carries both spellings" || bad "--json lost one of the two names"

# A full name is neither wrong nor doubled.
faramir vault add --editor /usr/local/sbin/writer3 full-name.sops.yml >/dev/null 2>&1 \
  && ok "a name that already carries the suffix is taken as it stands" || bad "a full name was refused"
[ -e /etc/faramir/secrets/full-name.sops.yml ] && ok "and is not doubled" \
  || bad "wrote $(echo /etc/faramir/secrets/full-name*)"

# The confirmation takes the name that was typed to get here.
printf 'bare-name\n' | faramir vault rm bare-name >/dev/null 2>&1 \
  && ok "rm takes the short name, at the argument and at the prompt" \
  || bad "the short name was refused at the confirmation"
printf 'full-name.sops.yml\n' | faramir vault rm full-name.sops.yml >/dev/null 2>&1 \
  && ok "and the full one still answers too" || bad "the full name was refused"

head_ "17. ls, refs and rm: the operator's view of the store"
cat > /usr/local/sbin/writer2 <<'EOF'
#!/bin/bash
printf 'inventory:\n  one: inventory-value-one\n  two: inventory-value-two\n' > "$1"
EOF
chmod 0755 /usr/local/sbin/writer2
faramir vault add --editor /usr/local/sbin/writer2 inventory.sops.yml >/dev/null 2>&1 \
  || bad "could not write the file this section is about"

faramir vault ls --json > /tmp/ls.json 2>/dev/null
jq -e --arg p /etc/faramir/secrets/inventory.sops.yml \
  '[.[]|select(.path==$p)]|length==1' /tmp/ls.json >/dev/null \
  && ok "ls lists the file" || bad "ls does not list it: $(cat /tmp/ls.json)"
jq -e --arg p /etc/faramir/secrets/inventory.sops.yml \
  '[.[]|select(.path==$p)|.refs[]]|sort==["inventory/one","inventory/two"]' /tmp/ls.json >/dev/null \
  && ok "and names the refs in it, read without decrypting" \
  || bad "ls got the refs wrong: $(jq -c --arg p /etc/faramir/secrets/inventory.sops.yml '[.[]|select(.path==$p)|.refs]' /tmp/ls.json)"
# The whole point of reading the structure rather than the values.
grep -q 'inventory-value-one' /tmp/ls.json && bad "PLAINTEXT IN THE LISTING" \
  || ok "and no value appears in the listing"
# By the name an operator types, which is not the order a glob returns once the
# directory holds a name that sorts differently from its path. A listing is read
# twice and diffed between hosts.
jq -e '[.[].name] == ([.[].name]|sort)' /tmp/ls.json >/dev/null \
  && ok "and the listing is sorted by name" \
  || bad "vault ls is not sorted: $(jq -c '[.[].name]' /tmp/ls.json)"
[ "$(jq -r 'length' /tmp/ls.json)" -ge 2 ] \
  && ok "with enough files for that to be an order" \
  || bad "only $(jq -r 'length' /tmp/ls.json) file(s) listed, too few to order"
jq -e --arg p /etc/faramir/secrets/inventory.sops.yml \
  '[.[]|select(.path==$p)|.drifted]==[false]' /tmp/ls.json >/dev/null \
  && ok "and reports it as agreeing with the rule" || bad "ls reports drift on a fresh file"

# refs is the broker's answer, and needs no root.
reload_daemons || bad "the daemons did not come back"
runuser -u op -- faramir refs > /tmp/refs.log 2>&1 \
  && ok "refs answers without root" || bad "refs needed root: $(tail -2 /tmp/refs.log)"
grep -q 'faramir://inventory/one' /tmp/refs.log \
  && ok "and the broker is serving what ls found" || bad "the broker is not serving it"

# THE REFUSAL: anything but the file's own name leaves it alone.
kept=1
for answer in "no" "" "y" "yes" "inventor" "inventory.sops"; do
  printf '%s\n' "$answer" | faramir vault rm inventory.sops.yml >/dev/null 2>&1
  # Stop at the first one that removed it: every answer after that is asked of
  # a file that is already gone, and would report a refusal that never happened.
  [ -e /etc/faramir/secrets/inventory.sops.yml ] \
    || { bad "answering '$answer' removed the file"; kept=0; break; }
done
[ "$kept" -eq 1 ] \
  && ok "only the file's own name removes it; no, an empty line, y, yes and a near miss do not"
# A closed stdin is a refusal too, not a prompt nobody answered.
faramir vault rm inventory.sops.yml </dev/null >/dev/null 2>&1
[ -e /etc/faramir/secrets/inventory.sops.yml ] && ok "and a closed stdin refuses" \
  || bad "a closed stdin removed the file"

printf 'inventory\n' | faramir vault rm inventory >/tmp/rm.log 2>&1 \
  && ok "the file's own name removes it" || bad "rm failed: $(tail -2 /tmp/rm.log)"
[ -e /etc/faramir/secrets/inventory.sops.yml ] && bad "the file is still there" \
  || ok "and the file is gone"
grep -q 'inventory/one' /tmp/rm.log && ok "it named the refs it was about to destroy" \
  || bad "rm did not say what went with the file"
# The log is what is left of a file nobody can read any more.
jq -r 'select(.op=="remove") | .refs[]' "$LOG" 2>/dev/null | grep -q 'inventory/one' \
  && ok "and the audit log keeps them" || bad "the removal record does not name the refs"

# rm reaches only the store: an unmanaged path is not this command's to delete.
faramir vault rm /etc/faramir/config.toml >/dev/null 2>&1 \
  && bad "removed a file outside the managed store" || ok "rm refuses an unmanaged path"
[ -e /etc/faramir/config.toml ] || bad "the config was deleted"

summary

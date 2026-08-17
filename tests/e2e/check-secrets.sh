#!/bin/bash
# Functional test of the secret lifecycle: edit, rekey, and what happens when the
# age key stops matching the ciphertext.
#
# The stakes are why this is worth a suite of its own.  Every other mistake here
# is recoverable by re-running something; re-encrypting to a recipient set that
# leaves the keeper out is not, and neither is losing the key.  So the tests are
# as much about what the tool REFUSES as about what it does.
#
# Sections 8 to 13 are the .sops.yaml a reader would not think to write: a rule
# taken from a directory that is not this install's, and shapes sops reads
# differently from how they look.  Each is a way the store ends up sealed to the
# wrong people, or written in the clear, with every command reporting success --
# which is why they are put to a real install rather than to a parser.
set -u
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

MANAGED=/etc/faramir/secrets/app.sops.yml
sum() { sha256sum "$MANAGED" | cut -c1-16; }
brokered() { runuser -u op -- faramir run --quiet -t 25 "$@" 2>&1; }
# reload the daemons onto a changed store.  reset-failed first and a settle
# after: a socket unit carries systemd's default start limit (5 starts / 10s),
# and this suite restarts them once per group, so without this the last group
# measures a host the earlier ones rate-limited into `failed`.
reload_daemons() {
  systemctl reset-failed faramir-keeper.socket faramir-keeper.service \
    faramir-broker.socket faramir-broker.service faramir-exec.socket >/dev/null 2>&1
  systemctl restart faramir-keeper.socket faramir-broker.socket >/dev/null 2>&1
  for _ in $(seq 20); do
    runuser -u op -- faramir list-secrets >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# This suite rotates db/password, adds a ref, and rewrites .sops.yaml.  Those
# values are shared: leak, stream, wrap, mcp and disclose all redact the
# original db/password, so a suite that leaves it rotated makes those fail when
# they run next against the same box.  Snapshot the store and rule now, restore
# them on the way out, and reload the daemons onto the restored file, so running
# this suite composes with the others rather than sabotaging them.  The exit
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
# The editor is where a person would be.  It records what it was handed, so the
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
if faramir sops edit --editor /usr/local/sbin/spy-editor "$MANAGED" >/tmp/edit.log 2>&1; then
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
# window rather than on the next request.  Polled to the interval plus slack,
# which is the claim: no restart, not instantaneous.
interval=$(grep -oP 'min_refresh_sec = \K[0-9]+' /etc/faramir/config.toml)
took=""
for i in $(seq $(( interval + 10 )) ); do
  refs=$(runuser -u op -- faramir list-secrets 2>/dev/null | tr '\n' ' ')
  case "$refs" in *new/ref*) took=$i; break;; esac
  sleep 1
done
[ -n "$took" ] && ok "the ref added in the editor is served after ${took}s, no restart (interval ${interval}s)" \
  || bad "the new ref is not being served within $(( interval + 10 ))s: $refs"
out=$(brokered --env V=secret://new/ref -- /bin/sh -c 'echo GOT=$V')
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
head_ "4. rekey --dry-run writes nothing"
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
faramir sops rekey --dry-run >/tmp/dry.log 2>&1
[ "$(sum)" = "$before" ] && ok "the file is byte-identical after a dry run" \
  || bad "a dry run rewrote the file"
grep -qiE "would|dry" /tmp/dry.log && ok "it reported what it would do: $(grep -iE 'would|dry' /tmp/dry.log | head -1 | cut -c1-70)" \
  || bad "a dry run said nothing useful: $(head -2 /tmp/dry.log)"

head_ "5. rekey to a second recipient, and the keeper can still read"
faramir sops rekey >/tmp/rekey.log 2>&1 && ok "rekey completed" || bad "rekey failed: $(tail -2 /tmp/rekey.log)"
[ "$(sum)" != "$before" ] && ok "the file was re-encrypted" || bad "the file did not change"
if grep -q "$SECOND" "$MANAGED"; then ok "the second recipient is now in the file's metadata"; else
  bad "the new recipient is not in the file"; fi
reload_daemons || bad "the daemons did not come back"
refs=$(runuser -u op -- faramir list-secrets 2>&1 | tr '\n' ' ')
echo "$refs" | grep -q "secret://new/ref" && ok "the keeper still decrypts everything after the rekey" \
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
if faramir sops rekey >/tmp/bad-rekey.log 2>&1; then
  bad "re-encrypting to a set without the keeper's key SUCCEEDED, which is unrecoverable"
else
  ok "refused: $(grep -oE 'does not list|would leave' /tmp/bad-rekey.log | head -1)"
fi
[ "$(sum)" = "$before" ] && ok "and the file is byte-identical, so nothing was half-written" \
  || bad "the refused rekey still modified the file"
# The proof that the refusal saved something: the keeper still reads it.
reload_daemons || bad "the daemons did not come back"
runuser -u op -- faramir list-secrets 2>&1 | grep -q "secret://new/ref" \
  && ok "the secrets still decrypt after the refusal" || bad "the refusal left the secrets unreadable"

head_ "7. an edit preserves who can read the file, whatever .sops.yaml now says"
# rekey applies a changed rule; edit must not, or editing a value would quietly
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
if faramir sops edit --editor /usr/local/sbin/spy-editor "$MANAGED" >/tmp/edit2.log 2>&1; then
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
runuser -u op -- faramir list-secrets 2>&1 | grep -q "secret://new/ref" \
  && ok "and the broker still decrypts it" || bad "the file is no longer readable"

# --------------------------------------------------------------------------
# The shapes below are the ones a reader would not think to try: a .sops.yaml
# written in a way an earlier version read differently from sops, and a rule
# taken from somewhere that is not this install.  Each is a way the store gets
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
# operator runs `sudo faramir sops edit` from wherever they are standing, which on
# this host is an enrolled tree the agent writes.  A rule found there deciding
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
if (cd "$PLANTED" && faramir sops edit --editor /usr/local/sbin/spy-editor "$MANAGED") \
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

head_ "9. rekey keeps a recipient named only under a merged key group"
# A key group may pull in others with `merge:`, and their keys seal the file
# exactly like the ones written inline.  A reader that stops at the top level
# re-encrypts the store without them, which takes a backup key's access away for
# good: re-running does not give it back.
rule <<YAML
  - path_regex: \.sops\.ya?ml\$
    key_groups:
      - age:
          - $KEEPER
YAML
faramir sops rekey >/tmp/narrow.log 2>&1 || bad "narrowing to the keeper alone failed: $(tail -2 /tmp/narrow.log)"
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
faramir sops rekey >/tmp/merge.log 2>&1 && ok "rekey completed under a merged key group" \
  || bad "rekey failed: $(tail -2 /tmp/merge.log)"
grep -q "$SECOND" "$MANAGED" \
  && ok "the recipient named only under merge: is in the file, so it can still read the store" \
  || bad "UNRECOVERABLE: rekey dropped the merged recipient, and re-running does not restore its access"
grep -q "$KEEPER" "$MANAGED" && ok "and so is the keeper's" || bad "the keeper was dropped"

head_ "10. a bare age: beside key_groups is the one sops ignores"
# sops reads a rule's `age` shorthand only where it has no key groups.  Reading
# both names a reader the rule does not grant, and would let a check report the
# keeper as still listed on a rule that seals the file without it.
rule <<YAML
  - path_regex: \.sops\.ya?ml\$
    age: $SECOND
    key_groups:
      - age:
          - $KEEPER
YAML
faramir sops rekey >/tmp/shorthand.log 2>&1 && ok "rekey completed" \
  || bad "rekey failed: $(tail -2 /tmp/shorthand.log)"
[ "$(recipients)" -eq 1 ] && ok "the file names one recipient, which is what sops would have sealed it to" \
  || bad "the file names $(recipients) recipients, so the ignored shorthand was applied"
grep -q "$SECOND" "$MANAGED" \
  && bad "the store is readable by a key the rule does not actually grant" \
  || ok "the key named only in the ignored shorthand is not a reader"
reload_daemons || bad "the daemons did not come back"
runuser -u op -- faramir list-secrets 2>&1 | grep -q "secret://new/ref" \
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
if faramir sops rekey >/tmp/tworule.log 2>&1; then
  bad "a two-rule .sops.yaml was accepted, so the store can be sealed to a set no rule names"
else
  ok "refused: $(grep -oE 'creation rules|updatekeys' /tmp/tworule.log | head -1)"
fi
[ "$(sum)" = "$before" ] && ok "and the file is byte-identical" || bad "the refused rekey wrote to the file"

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
if faramir sops rekey >/tmp/shamir.log 2>&1; then
  bad "rekey flattened a split data key, so any single key now opens what took two"
else
  ok "rekey refused: $(grep -oE 'shamir_threshold' /tmp/shamir.log | head -1)"
fi
editor "sed -i 's/edited/edited/' \"\$1\""
if faramir sops edit --editor /usr/local/sbin/spy-editor "$MANAGED" >/tmp/shamir-edit.log 2>&1; then
  bad "edit wrote a split-key store back as one group, which removes the split silently"
else
  ok "edit refused it too: $(grep -oE 'shamir_threshold' /tmp/shamir-edit.log | head -1)"
fi
ran && bad "the editor ran before the refusal" || ok "and the editor never ran"
[ "$(sum)" = "$before" ] && ok "the store is byte-identical after both refusals" \
  || bad "a refused command still wrote to the file"

head_ "13. an edit no rule covers is refused before the editor opens"
# sops refuses a file no creation rule matches, and it refuses it at the encrypt,
# which is after the editor has exited.  Learning then costs the operator
# everything they typed, so the question is put while there is nothing to lose.
rule <<YAML
  - path_regex: ^nowhere-near-the-store/.*\.sops\.yml\$
    key_groups:
      - age:
          - $KEEPER
YAML
before=$(sum)
editor "sed -i 's/edited/rewritten/' \"\$1\""
if faramir sops edit --editor /usr/local/sbin/spy-editor "$MANAGED" >/tmp/uncovered.log 2>&1; then
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

summary

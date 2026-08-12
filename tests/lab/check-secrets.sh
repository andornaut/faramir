#!/bin/bash
# Functional test of the secret lifecycle: edit, rekey, and what happens when the
# age key stops matching the ciphertext.
#
# The stakes are why this is worth a suite of its own.  Every other mistake here
# is recoverable by re-running something; re-encrypting to a recipient set that
# leaves the keeper out is not, and neither is losing the key.  So the tests are
# as much about what the tool REFUSES as about what it does.
set -u
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
head_() { printf '\n== %s\n' "$1"; }

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
if faramir edit --editor /usr/local/sbin/spy-editor "$MANAGED" >/tmp/edit.log 2>&1; then
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
# [secrets] refresh_interval_sec bounds how often the broker may ask the keeper
# whether a file changed, so the pickup is on the first request after that
# window rather than on the next request.  Polled to the interval plus slack,
# which is the claim: no restart, not instantaneous.
interval=$(grep -oP 'refresh_interval_sec = \K[0-9]+' /etc/faramir/config.toml)
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
faramir rekey --dry-run >/tmp/dry.log 2>&1
[ "$(sum)" = "$before" ] && ok "the file is byte-identical after a dry run" \
  || bad "a dry run rewrote the file"
grep -qiE "would|dry" /tmp/dry.log && ok "it reported what it would do: $(grep -iE 'would|dry' /tmp/dry.log | head -1 | cut -c1-70)" \
  || bad "a dry run said nothing useful: $(head -2 /tmp/dry.log)"

head_ "5. rekey to a second recipient, and the keeper can still read"
faramir rekey >/tmp/rekey.log 2>&1 && ok "rekey completed" || bad "rekey failed: $(tail -2 /tmp/rekey.log)"
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
if faramir rekey >/tmp/bad-rekey.log 2>&1; then
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
if faramir edit --editor /usr/local/sbin/spy-editor "$MANAGED" >/tmp/edit2.log 2>&1; then
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

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

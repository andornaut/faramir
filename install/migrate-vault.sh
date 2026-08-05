#!/usr/bin/env bash
# Phase 2 -- convert one ansible-vault file to a sops-encrypted file.
#
# Run this as the OPERATOR, on a machine the operator trusts, NOT through the
# agent.  It necessarily handles plaintext: the intermediate file is written to
# /dev/shm with mode 0600 and removed on exit, including on error.
#
#   migrate-vault.sh group_vars/all/vault.yml group_vars/all/vault.sops.yml
#
# Var names are preserved exactly, so playbooks need no change beyond the
# lookup mechanism.
set -euo pipefail

SRC="${1:?usage: migrate-vault.sh <vault.yml> <out.sops.yml>}"
DST="${2:?usage: migrate-vault.sh <vault.yml> <out.sops.yml>}"
VAULT_PASSWORD_FILE="${VAULT_PASSWORD_FILE:-${ANSIBLE_VAULT_PASSWORD_FILE:-}}"

command -v sops >/dev/null || { echo "sops not found" >&2; exit 1; }
command -v ansible-vault >/dev/null || { echo "ansible-vault not found" >&2; exit 1; }
[[ -f $SRC ]] || { echo "no such file: $SRC" >&2; exit 1; }
[[ -e $DST ]] && { echo "refusing to overwrite $DST" >&2; exit 1; }
[[ -d $(dirname "$DST") ]] || { echo "no such directory: $(dirname "$DST")" >&2; exit 1; }

# sops finds .sops.yaml by walking up from the file it is encrypting, and picks
# a creation rule by matching that file's path.  The plaintext lives in
# /dev/shm, which matches nothing, so the destination path has to be named
# explicitly or sops exits with "no matching creation rules".
DST_ABS="$(cd "$(dirname "$DST")" && pwd)/$(basename "$DST")"

TMPDIR_SHM="$(mktemp -d /dev/shm/vault-migrate.XXXXXX)"
chmod 700 "$TMPDIR_SHM"
trap 'shred -u "$TMPDIR_SHM"/* 2>/dev/null || true; rm -rf "$TMPDIR_SHM"' EXIT INT TERM
PLAIN="$TMPDIR_SHM/plain.yml"

echo "==> decrypting $SRC"
if [[ -n $VAULT_PASSWORD_FILE ]]; then
  ansible-vault view --vault-password-file "$VAULT_PASSWORD_FILE" "$SRC" >"$PLAIN"
else
  ansible-vault view "$SRC" >"$PLAIN"
fi
chmod 600 "$PLAIN"

echo "==> encrypting to $DST"
# Encrypt into /dev/shm first: a redirect straight to $DST would leave an empty
# file behind on failure, and the -e guard above would then block the retry.
ENCRYPTED="$TMPDIR_SHM/out.sops.yml"
if sops --help 2>&1 | grep -q -- '--filename-override'; then
  sops --encrypt --filename-override "$DST_ABS" "$PLAIN" >"$ENCRYPTED"
elif [[ -n ${AGE_RECIPIENT:-} ]]; then
  sops --encrypt --age "$AGE_RECIPIENT" "$PLAIN" >"$ENCRYPTED"
else
  echo "this sops predates --filename-override; re-run with AGE_RECIPIENT=age1..." >&2
  exit 1
fi
cat "$ENCRYPTED" >"$DST"

echo "==> verifying round trip"
if ! diff <(sops --decrypt "$DST") "$PLAIN" >/dev/null; then
  rm -f "$DST"
  echo "round trip FAILED; $DST removed" >&2
  exit 1
fi

echo "==> $(grep -c ':' "$PLAIN") key(s) migrated (names unchanged)"
cat <<EOF

Done: $DST

Before deleting $SRC and the vault password file:
  1. Point [secrets].files in /etc/secretd/config.toml at $DST.
  2. systemctl reload secretd
  3. Run a real playbook end to end through secure-run and confirm it works.

Then, and only then:
  git rm $SRC && rm -f "\$VAULT_PASSWORD_FILE"

IMPORTANT: git history still contains the plaintext-equivalent vault blob and
anyone with the old vault password can read it. Rotate every credential that
was ever committed, or rewrite history (git filter-repo) and force-push. Do
not skip this -- moving to sops does not un-leak what is already in the log.
EOF

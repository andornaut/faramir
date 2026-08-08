#!/usr/bin/env bash
# Convert one ansible-vault file to a sops-encrypted file.  Not a numbered
# phase: run it once per vault file, whenever you migrate, after phase 2.
#
# Run this as the OPERATOR, on a machine the operator trusts, NOT through the
# agent.  It necessarily handles plaintext: the intermediate file is written to
# /dev/shm with mode 0600 and removed on exit, including on error.
#
#   migrate-vault.sh group_vars/all/vault.yml \
#       /etc/faramir/secrets/<consumer>.sops.yml
#
# The destination belongs in /etc/faramir/secrets, outside every home: a home is
# not mounted until its owner logs in, so a store inside one leaves the broker
# with an empty value set at boot and is unreadable to any unattended job.
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

# Ansible auto-loads every .yml under group_vars/ and host_vars/ as a vars file.
# A sops file is valid YAML, so it loads without error and binds each var to its
# ENC[...] ciphertext; since "vault" sorts after "vars", it also overwrites the
# lookup('env', ...) mapping.  Nothing fails.  Hosts get configured with the
# ciphertext of the credential instead of the credential.
if [[ $DST =~ (^|/)(group_vars|host_vars)/ ]]; then
  echo "refusing to write $DST" >&2
  echo "Ansible auto-loads group_vars/ and host_vars/, and would bind every var" >&2
  echo "to its ENC[...] ciphertext instead of the injected value.  Use a" >&2
  echo "directory Ansible does not read, e.g. secrets/$(basename "$DST")." >&2
  exit 1
fi

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
# Compared as data, not as bytes.  sops re-serialises YAML when it decrypts:
# long scalars are re-wrapped, quoting style can change, the document marker can
# move.  A byte comparison calls all of that a failure for a file whose values
# are identical, and then deletes the output, which is the one outcome that
# loses the work.
#
# The byte comparison stays as the fallback where PyYAML is missing.  It is
# stricter than it needs to be rather than laxer: a false failure leaves the
# vault in place and says so, where a false pass would migrate a file that
# quietly lost a key.
verified=0
if python3 -c 'import yaml' 2>/dev/null; then
  python3 - "$DST" "$PLAIN" <<'PYEOF' || verified=1
import subprocess, sys, yaml

dst, plain = sys.argv[1], sys.argv[2]
decrypted = subprocess.run(["sops", "--decrypt", dst], capture_output=True, text=True)
if decrypted.returncode != 0:
    sys.stderr.write(decrypted.stderr)
    sys.stderr.write("could not decrypt what was just written\n")
    sys.exit(1)

before = yaml.safe_load(open(plain)) or {}
after = yaml.safe_load(decrypted.stdout) or {}
if before == after:
    sys.exit(0)

# Names, never values.  This runs on the operator's own terminal, but the names
# alone say what to look at, and a value printed here is a value in a scrollback.
missing = sorted(set(before) - set(after))
unexpected = sorted(set(after) - set(before))
changed = sorted(k for k in set(before) & set(after) if before[k] != after[k])
for label, names in (("missing", missing), ("unexpected", unexpected), ("changed", changed)):
    if names:
        sys.stderr.write("%s: %s\n" % (label, ", ".join(names)))
sys.exit(1)
PYEOF
else
  diff <(sops --decrypt "$DST") "$PLAIN" >/dev/null || verified=1
fi

if [[ $verified -ne 0 ]]; then
  rm -f "$DST"
  echo "round trip FAILED; $DST removed" >&2
  exit 1
fi

echo "==> $(grep -c ':' "$PLAIN") key(s) migrated (names unchanged)"
cat <<EOF

Done: $DST

Before deleting $SRC and the vault password file:
  1. Point [secrets].files in /etc/faramir/config.toml at $DST.
  2. systemctl reload faramir-broker
  3. Run a real playbook end to end through faramir run and confirm it works.

Then, and only then:
  git rm $SRC && rm -f "\$VAULT_PASSWORD_FILE"
EOF

# Asked rather than asserted.  A vault that was gitignored from the start is
# not in the history, and telling its owner to rotate every credential anyway
# is how a warning gets learned as noise.  Only the repository knows which case
# this is, so ask it.
if git -C "$(dirname "$SRC")" rev-parse --git-dir >/dev/null 2>&1 &&
   [[ -n $(git -C "$(dirname "$SRC")" log --all --oneline -- "$(basename "$SRC")" 2>/dev/null) ]]; then
  cat <<EOF

IMPORTANT: $SRC is in this repository's history, so the plaintext-equivalent
blob is still there and anyone with the old vault password can read it.
Rotate every credential that was ever committed, or rewrite history with
git filter-repo and force-push. Moving to sops does not un-leak what is
already in the log.
EOF
else
  cat <<EOF

$SRC was never committed to this repository, so there is no vault blob in the
history and nothing to rotate on that account. Check any other clone or backup
that might have one before assuming the same of them.
EOF
fi

#!/usr/bin/env bash
# Phase 2 -- generate the age keypair and wire the repo up for sops.
#
# The private key ends up at /etc/faramir/age.key, 0400 owned by the KEEPER,
# not the broker.  Every brokered command runs as the broker's uid, so a key
# the broker could read is a key any command could read.  The keeper reads it
# through systemd's LoadCredential= and serves decrypted values only.
set -euo pipefail

BROKER_USER="${BROKER_USER:-faramir-broker}"
KEEPER_USER="${KEEPER_USER:-faramir-keeper}"
GROUP="${DEVWORK_GROUP:-devwork}"
KEY=/etc/faramir/age.key
AGENT_USER="${AGENT_USER:-agent}"
AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)" || AGENT_HOME=""
# The agent's working tree, which is also where brokered commands run and where
# the sops files live.  WORKTREE is what the other three phases call it, and a
# one-command install passes it to all of them; REPO stays accepted so an
# existing invocation keeps working.
REPO="${REPO:-${WORKTREE:-${AGENT_HOME:-/home/${AGENT_USER}}/work/repo}}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

# faramir mints the keypair itself, so the host needs no age binary.  Prefer an
# installed faramir; fall back to the built one, so this phase works whichever
# order the installer scripts are run in.
KEYGEN=""
for candidate in /usr/local/bin/faramir "$(dirname "${BASH_SOURCE[0]}")/../bin/faramir"; do
  [[ -x $candidate ]] && { KEYGEN="$candidate"; break; }
done
[[ -n $KEYGEN ]] || {
  echo "faramir not found; run 'make build' first (or install/30-install-broker.sh)" >&2
  exit 1
}
# sops is still required: it is what encrypts and edits the managed files.
command -v sops >/dev/null || { echo "install sops first (https://github.com/getsops/sops/releases)" >&2; exit 1; }

install -d -m 0755 -o root -g root /etc/faramir

if [[ -f $KEY ]]; then
  say "keeping existing ${KEY}"
else
  say "generating age keypair"
  # Subshell: a bare 'umask 077' here would leak into everything below, and
  # .sops.yaml has to stay group-readable.  faramir keygen writes 0400 and
  # refuses to clobber, so an existing key cannot be destroyed by a re-run.
  (umask 077; "$KEYGEN" keygen -o "$KEY" >/dev/null)
fi
# Re-asserted every run, not just on creation: a host that installed before the
# keeper existed still has this key owned by the broker, where every brokered
# command could read it.
# CLEANUP (added 2026-08-05): the chown can drop back inside the else branch
# once every host has run this script once.
id -u "$KEEPER_USER" >/dev/null 2>&1 || {
  echo "no such user: ${KEEPER_USER}; run install/10-accounts.sh first" >&2
  exit 1
}
chown "$KEEPER_USER:$KEEPER_USER" "$KEY"
chmod 0400 "$KEY"

PUB="$(grep -o 'age1[0-9a-z]*' "$KEY" | tail -1)"
say "public key: ${PUB}"

# Additional age recipients for .sops.yaml, space or comma separated.
#
# The keeper is the only recipient by default, which means the operator cannot
# read the files they are responsible for: editing one, rotating a credential
# or reading a value back all need a recipient that is not the keeper.  Adding
# the operator's own key is the ordinary case, and it changes nothing about
# what the agent can reach: the agent has no age key either way.
#
# Mint one with:  faramir keygen -o ~/.config/sops/age/keys.txt
RECIPIENTS=("$PUB")
# Space or comma separated, and usually unset, so default before splitting:
# set -u makes a bare expansion of an unset name fatal.
_extra_recipients="${EXTRA_AGE_RECIPIENTS:-}"
for extra in ${_extra_recipients//,/ }; do
  [[ -n $extra ]] || continue
  [[ $extra == age1* ]] || {
    echo "not an age recipient: ${extra}" >&2
    exit 1
  }
  RECIPIENTS+=("$extra")
  say "extra recipient: ${extra}"
done

if [[ -d $REPO ]]; then
  SOPS_YAML="${REPO}/.sops.yaml"
  if [[ -f $SOPS_YAML ]]; then
    say "keeping existing ${SOPS_YAML}"
  else
    say "writing ${SOPS_YAML}"
    cat >"$SOPS_YAML" <<EOF
# Which files sops encrypts, and to whom.  Any *.sops.yml, wherever it sits:
# a rule naming one layout refuses to encrypt a file kept anywhere else, and
# reports it as "no matching creation rules found".
# 'encrypted_regex' leaves keys readable and encrypts only values, so diffs
# stay per-key and reviewable.
creation_rules:
  - path_regex: \.sops\.ya?ml\$
    key_groups:
      - age:
$(printf '          - %s\n' "${RECIPIENTS[@]}")
EOF
    # Both the agent and the broker are non-root and must read this to encrypt,
    # so 0640 is only safe once the group is actually right.  Fall back to 0644
    # rather than leave a file only root can read.
    if chgrp "$GROUP" "$SOPS_YAML" 2>/dev/null; then
      chmod 0640 "$SOPS_YAML"
    else
      say "group ${GROUP} not found; leaving ${SOPS_YAML} world-readable"
      chmod 0644 "$SOPS_YAML"
    fi
  fi
fi

cat <<EOF

Public key (also add this to .sops.yaml in the agent's working tree):
  ${PUB}

Next: convert each ansible-vault file with

  install/migrate-vault.sh group_vars/all/vault.yml group_vars/all/vault.sops.yml

then verify a real playbook run through the broker BEFORE deleting the old
vault files and the vault password file.
EOF

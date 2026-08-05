#!/usr/bin/env bash
# Phase 2 -- generate the age keypair and wire the repo up for sops.
#
# The private key ends up at /etc/secretd/age.key, 0400 secretd:secretd.  It is
# never copied anywhere else; the broker reads it through systemd's
# LoadCredential=, so it is not even readable from the broker's own $PATH view.
set -euo pipefail

BROKER_USER="${BROKER_USER:-secretd}"
GROUP="${DEVWORK_GROUP:-devwork}"
KEY=/etc/secretd/age.key
REPO="${REPO:-/srv/ansible-ctrl}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

command -v age-keygen >/dev/null || { echo "install age first (apt install age)" >&2; exit 1; }
command -v sops >/dev/null || { echo "install sops first (https://github.com/getsops/sops/releases)" >&2; exit 1; }

install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_USER" /etc/secretd

if [[ -f $KEY ]]; then
  say "keeping existing ${KEY}"
else
  say "generating age keypair"
  # Subshell: a bare 'umask 077' here would leak into everything below, and
  # .sops.yaml has to stay group-readable.
  (umask 077; age-keygen -o "$KEY" 2>/dev/null)
  chown "$BROKER_USER:$BROKER_USER" "$KEY"
  chmod 0400 "$KEY"
fi

PUB="$(grep -o 'age1[0-9a-z]*' "$KEY" | tail -1)"
say "public key: ${PUB}"

if [[ -d $REPO ]]; then
  SOPS_YAML="${REPO}/.sops.yaml"
  if [[ -f $SOPS_YAML ]]; then
    say "keeping existing ${SOPS_YAML}"
  else
    say "writing ${SOPS_YAML}"
    cat >"$SOPS_YAML" <<EOF
# Which files sops encrypts, and to whom.
# 'encrypted_regex' leaves keys readable and encrypts only values, so diffs
# stay per-key and reviewable.
creation_rules:
  - path_regex: (^|/)(group_vars|host_vars)/.*\.sops\.ya?ml\$
    key_groups:
      - age:
          - ${PUB}
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

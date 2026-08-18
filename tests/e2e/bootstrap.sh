#!/bin/bash
# Bring the host up the way an operator would: install faramir, write the first
# secrets file, enrol a working tree for a coding agent.
#
# Idempotent, so it can be re-run against a container that is already part way
# up without the first existing account aborting the rest.
set -eu

SECRETS=/etc/faramir/secrets/app.sops.yml
PROJECT=/home/op/project

step() { printf '\n== %s\n' "$1"; }

step "the faramir binary"
install -m 0755 /opt/faramir/faramir /usr/local/bin/faramir
faramir --version

step "the account the coding agent runs as"
# In faramir's model that is the operator's own uid: the agent is a program in
# their session, not a service account.
id op >/dev/null 2>&1 || useradd -m -s /bin/bash op
# systemd-logind is what creates this on a real host; there is no login here.
install -d -o op -g op -m 0700 /run/user/"$(id -u op)"

step "faramir init"
if [ -f /etc/faramir/config.toml ]; then
  echo "already installed at /etc/faramir"
else
  faramir init --agent-user op >/tmp/init.log 2>&1 || {
    tail -20 /tmp/init.log; exit 1; }
  echo "installed; see /tmp/init.log"
fi

step "the first managed file"
# Creating one needs sops and two flags: which .sops.yaml applies is resolved
# from the working directory upward, so encrypting into the secrets directory
# from anywhere else finds no creation rules.  Every edit after this is
# `faramir secret edit`, which needs neither flag.
#
# short/pin is deliberately under [secret] min_length: it is the value the
# redactor refuses to cover, and several checks are about how that is reported.
if [ -f "$SECRETS" ]; then
  echo "already written"
else
  umask 077
  cat > /tmp/plain.yml <<'BODY'
db:
  password: hunter2-correct-horse-battery
api:
  token: tok_live_0PENSESAME_9911
router:
  admin: "r0uter!pass&word<tricky>"
short:
  pin: "8341"
BODY
  # shellcheck disable=SC2094  # --filename-override names the file for sops's
  # creation rules; it is not opened, and the target does not exist yet.
  sops --config /etc/faramir/.sops.yaml --encrypt \
    --filename-override "$SECRETS" /tmp/plain.yml > "$SECRETS"
  shred -u /tmp/plain.yml
  chown root:faramir-keeper "$SECRETS"
  chmod 0640 "$SECRETS"
  echo "wrote $SECRETS"
fi

step "the tree the agent works in"
install -d -o op -g op "$PROJECT"
faramir init-project --agent-user op --agent claude "$PROJECT" >/tmp/project.log 2>&1 || {
  tail -20 /tmp/project.log; exit 1; }
echo "enrolled $PROJECT"

step "restart onto what is now on disk"
systemctl restart faramir-keeper.socket faramir-exec.socket faramir-broker.socket
# The broker polls the keeper on an interval rather than on every request; wait
# for the value set rather than sleeping a guess.
for _ in $(seq 20); do
  refs=$(runuser -u op -- faramir secret refs 2>/dev/null || true)
  case "$refs" in *db/password*) break;; esac
  sleep 1
done

step "what the broker is serving"
runuser -u op -- faramir secret refs
echo
echo "refs refused at load (operator-facing only):"
faramir broker --check 2>/dev/null | jq -c '.secrets.not_redactable' || true

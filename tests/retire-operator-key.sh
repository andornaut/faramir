#!/usr/bin/env bash
# Retire the operator's own age identity, once the keeper is the only thing that
# needs to open the store.  That key decrypts every managed file and is readable
# by the account a coding agent runs as, so removing it is what makes the group
# and ownership work load-bearing.
#
# Run as the operator, not under sudo.  It sudos where it needs to.
#
#   tests/retire-operator-key.sh [--config-dir DIR] [--host HOST]... [--shred]
#
# Two modes, chosen by what it finds:
#
#   the key is in place    move it aside, re-verify without it, restore on any
#                          failure
#   already stashed        search only, for the recipients check that decides
#                          whether the stash is safe to destroy
#
# Destroying it is not automatic: pass --shred to be prompted after every check
# passes.

set -uo pipefail

CONFIG_DIR=$HOME/.config/faramir
KEY=$HOME/.config/sops/age/keys.txt
STASH=/root/faramir-operator-key.retired
SHRED=0
HOSTS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --config-dir) CONFIG_DIR=$2; shift 2 ;;
    --host) HOSTS+=("$2"); shift 2 ;;
    --shred) SHRED=1; shift ;;
    -h | --help) sed -n '2,25p' "$0"; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

SECRETS_DIR=$CONFIG_DIR/secrets
HERE=$(cd "$(dirname "$0")" && pwd)

say() { printf '\n\033[1m%s\033[0m\n' "$1"; }
ok() { printf '  \033[32mok\033[0m      %s\n' "$1"; }
no() { printf '  \033[31mFAIL\033[0m    %s\n' "$1"; }
note() { printf '  --      %s\n' "$1"; }

restore() {
  if sudo test -f "$STASH"; then
    sudo mv "$STASH" "$KEY" && note "restored $KEY"
  fi
}

die() { no "$1"; restore; exit 1; }

verify() {
  local out=/tmp/faramir-verify.$$
  if "$HERE/verify-install.sh" "$CONFIG_DIR" >"$out" 2>&1; then
    ok "verify-install.sh passes"
    rm -f "$out"
    return 0
  fi
  no "verify-install.sh fails. Output:"
  cat "$out"
  rm -f "$out"
  return 1
}

# offer_shred is the only destructive path, and it asks first.
offer_shred() {
  if [ "$SHRED" -ne 1 ]; then
    note "it is stashed at $STASH, still restorable with:"
    note "    sudo mv $STASH $KEY"
    note "destroy it when you are satisfied, with:"
    note "    sudo shred -u $STASH"
    note "or re-run this with --shred to be prompted for it"
    return
  fi
  printf '  About to destroy %s. This cannot be undone.\n' "$STASH"
  printf '  Anything encrypted to it and not found above becomes unreadable.\n'
  printf '  Type DESTROY to continue: '
  read -r answer
  if [ "$answer" = "DESTROY" ]; then
    sudo shred -u "$STASH" && ok "destroyed $STASH"
  else
    note "not destroyed; it is still at $STASH"
  fi
}

say "Preconditions"
sudo -v || { no "sudo is required"; exit 1; }

# A key in place is a retirement; a stash and no key is the search that precedes
# destroying it.
MODE=retire
if [ -r "$KEY" ]; then
  ok "found $KEY"
  if sudo test -e "$STASH"; then
    no "$STASH already exists as well; move one of them aside first"
    exit 1
  fi
elif sudo test -f "$STASH"; then
  MODE=search
  ok "already retired; the stashed key is $STASH"
  note "search only: nothing will be moved"
else
  no "no key at $KEY and nothing stashed at $STASH; nothing to do"
  exit 1
fi

verify || exit 1

if [ "$MODE" = retire ]; then
  mine=$(age-keygen -y "$KEY" 2>/dev/null)
else
  mine=$(sudo age-keygen -y "$STASH" 2>/dev/null)
fi
[ -n "${mine:-}" ] || { no "could not read a public key out of the identity"; exit 1; }
ok "public key: $mine"

if [ "$MODE" = retire ]; then
  store_file=$(sudo find "$SECRETS_DIR" -maxdepth 1 -type f -name '*.sops.y*ml' 2>/dev/null | head -1)
  [ -n "$store_file" ] || { no "no managed sops file under $SECRETS_DIR"; exit 1; }
  ok "store file: $store_file"

  if sudo grep -qF -- "$mine" "$store_file"; then
    ok "the key is a recipient of the store, so retiring it changes something"
  else
    note "the key is NOT a recipient of $store_file"
    note "retiring it changes nothing here; stopping so you can decide deliberately"
    exit 0
  fi

  before_count=$(faramir status 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["secrets"]["count"])' 2>/dev/null)
  [ -n "${before_count:-}" ] || { no "could not read the broker's secret count"; exit 1; }
  ok "broker currently serves $before_count secret(s)"
fi

say "Anything else encrypted to this key"
found=0
while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  no "also a recipient of: $hit"
  found=1
done < <(grep -rl --include='*.yml' --include='*.yaml' --include='*.json' --include='*.env' \
  -- "$mine" "$HOME/src" "$HOME/.config" "$HOME/.local" 2>/dev/null | grep -v '/\.git/')
for host in ${HOSTS+"${HOSTS[@]}"}; do
  reached=0
  while IFS= read -r hit; do
    reached=1
    [ "$hit" = "__searched__" ] && continue
    no "also a recipient of $host:$hit"
    found=1
  done < <(ssh -o BatchMode=yes -o ConnectTimeout=10 "$host" \
    "grep -rl --include='*.yml' --include='*.yaml' --include='*.json' -- '$mine' \
     \$HOME /etc 2>/dev/null; echo __searched__" 2>/dev/null)
  if [ "$reached" -eq 1 ]; then
    ok "searched $host"
  else
    # Not the same as finding nothing, and the difference matters before a shred.
    no "could not search $host; treat its result as unknown"
    found=1
  fi
done
if [ "$found" -eq 0 ]; then
  ok "nothing else in the searched trees uses it"
  note "not searched: backups, removable media, hosts not passed with --host"
else
  if [ "$MODE" = retire ]; then
    no "other files are encrypted to this key; retiring it would lock you out of them"
    exit 1
  fi
  say "Result"
  no "do not destroy $STASH until the above is resolved"
  exit 1
fi

if [ "$MODE" = search ]; then
  say "Result"
  ok "the stash opens nothing that was found"
  offer_shred
  exit 0
fi

say "Retiring"
sudo mv "$KEY" "$STASH" || { no "could not move the key"; exit 1; }
ok "moved to $STASH (reversible)"

say "Re-verifying without it"
after_count=$(faramir status 2>/dev/null |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["secrets"]["count"])' 2>/dev/null)
[ "${after_count:-}" = "$before_count" ] || die "broker now serves '${after_count:-nothing}', was $before_count"
ok "broker still serves $after_count secret(s)"

out=$(sudo faramir edit -editor /bin/true "$(basename "$store_file")" 2>&1)
case "$out" in
  *unchanged*) ok "sudo faramir edit still opens the store" ;;
  *) die "faramir edit failed without the key: $out" ;;
esac

verify || die "restoring"

say "Result"
ok "every check passed with the key out of the way"
offer_shred

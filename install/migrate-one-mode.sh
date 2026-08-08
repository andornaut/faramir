#!/usr/bin/env bash
# CLEANUP (added 2026-08-07): one-shot migration from the two-account design to
# the one where the coding agent runs as the operator.  Delete this once every
# host that ran the old design has been migrated; there is exactly one.
#
# What it does, in order, stopping at the first failure:
#
#   1. repoint /etc/faramir/config.toml at the operator's own checkout
#   2. register the hook in the operator's ~/.claude/settings.json
#   3. remove the stale tree an earlier default created under /srv
#   4. re-encrypt the ansible-vault file as sops, if that has not been done
#   5. map the var names to the environment, if that has not been done
#   6. reload the broker and check it actually loaded something
#
# What it deliberately does NOT do, because both destroy something:
#
#   - remove group_vars/all/vault.yml.  Nothing is lost by keeping it, the sops
#     file is additive, and a playbook run is what proves the new path works.
#   - remove the agent account or its home.  `make faramir_cleanup` in the
#     ansible-ctrl repo owns that, and refuses while a checkout under that home
#     holds work that is nowhere else.
#
# Idempotent: every step checks whether it has already been done.  Safe to
# re-run after fixing whatever stopped it.
set -euo pipefail

# Resolved before anything changes directory: step 4 runs a sibling script from
# this checkout while the working directory is the ansible one, and a relative
# path would look for it there.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WORKTREE="${WORKTREE:-$HOME/src/github.com/andornaut/ansible-ctrl}"
VAULT="${VAULT:-group_vars/all/vault.yml}"
SOPS_FILE="${SOPS_FILE:-secrets/vault.sops.yml}"
VARS_FILE="${VARS_FILE:-group_vars/all/vars.yml}"
STAMP="$(date +%Y%m%d-%H%M%S)"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
skip() { printf '    \033[33malready done\033[0m  %s\n' "$*"; }
die()  { printf '\033[31m!!\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -ne 0 ]] || die "run as the operator, not as root; it calls sudo where it needs to"
[[ -d $WORKTREE ]] || die "no checkout at ${WORKTREE} (set WORKTREE=)"
command -v python3 >/dev/null || die "python3 is needed to merge the settings file"

# Asked for once, up front: a migration that stops halfway to prompt is a
# migration whose later steps run against a half-changed system.
say "this needs sudo for the config and the broker"
sudo -v

# --------------------------------------------------------------------------
say "1/6  config.toml -> ${WORKTREE}"
# Phase 3 never overwrites an installed config; it writes the new one beside it.
# Moving it into place is the operator's decision, which is this line.
# The .dist is what gets installed, so it is what has to name the tree.  Testing
# only the old config would install a .dist built with a different WORKTREE, and
# would take this branch again on every re-run, leaving a fresh .bak each time.
if [[ -f /etc/faramir/config.toml.dist ]] &&
   ! grep -qF "$WORKTREE" /etc/faramir/config.toml 2>/dev/null &&
   grep -qF "$WORKTREE" /etc/faramir/config.toml.dist; then
  sudo cp -a /etc/faramir/config.toml "/etc/faramir/config.toml.bak-${STAMP}"
  sudo cp -a /etc/faramir/config.toml.dist /etc/faramir/config.toml
  say "     kept the old one at /etc/faramir/config.toml.bak-${STAMP}"
elif grep -qF "$WORKTREE" /etc/faramir/config.toml 2>/dev/null; then
  skip "config.toml already names ${WORKTREE}"
else
  die "no /etc/faramir/config.toml.dist to install; run 'sudo make install' first"
fi

# Only that it parses.  default_cwd is no longer set by the shipped configs: a
# brokered command runs where its caller was.
/usr/local/bin/faramir-broker -c /etc/faramir/config.toml --print-default-cwd >/dev/null ||
  die "/etc/faramir/config.toml does not parse"

# --------------------------------------------------------------------------
say "2/6  the hook, in ${HOME}/.claude/settings.json"
# Merged rather than copied: the settings file is the operator's, and phase 4
# writes a .dist precisely so that nothing here overwrites it.  The hook is what
# redacts the output of everything the agent runs, so a session without it is
# covered only for brokered commands.
if [[ ! -f ${HOME}/.claude/settings.json.dist ]]; then
  skip "no settings.json.dist; nothing to merge"
elif grep -q faramir-guard "${HOME}/.claude/settings.json" 2>/dev/null; then
  skip "settings.json already registers faramir-guard"
else
  cp -a "${HOME}/.claude/settings.json" "${HOME}/.claude/settings.json.bak-${STAMP}" 2>/dev/null || true
  python3 - "$HOME/.claude/settings.json" "$HOME/.claude/settings.json.dist" <<'PY'
import json, sys, os

target, dist = sys.argv[1], sys.argv[2]
have = json.load(open(target)) if os.path.exists(target) else {}
want = json.load(open(dist))

# Union, not replacement: the deny list here is faramir's, and the operator's
# own entries have to survive it.
deny = have.setdefault("permissions", {}).setdefault("deny", [])
for rule in want.get("permissions", {}).get("deny", []):
    if rule not in deny:
        deny.append(rule)

# Appended to whatever PreToolUse matchers are already there.  Two hooks on one
# event both run, and the second would rewrite the first's rewrite, so this
# refuses to add a second faramir-guard rather than nesting one.
hooks = have.setdefault("hooks", {}).setdefault("PreToolUse", [])
if not any("faramir-guard" in json.dumps(entry) for entry in hooks):
    hooks.extend(want.get("hooks", {}).get("PreToolUse", []))

with open(target, "w") as fh:
    json.dump(have, fh, indent=2)
    fh.write("\n")
PY
  chmod 600 "${HOME}/.claude/settings.json"
  say "     merged; the old file is at settings.json.bak-${STAMP}"
fi

# --------------------------------------------------------------------------
say "3/6  the stale tree under /srv"
# An earlier default put the worktree here.  Nothing reads it now, and what it
# holds (.mcp.json, .sops.yaml, CLAUDE.md) is regenerated by the install phases.
# Never when the tree being migrated to lives there.  /srv/faramir/worktree is
# the installer's own default, so an operator who ran `sudo make install` with
# shipped defaults would otherwise lose the tree phase 1 had just built.
if [[ $WORKTREE == /srv/faramir || $WORKTREE == /srv/faramir/* ]]; then
  skip "/srv/faramir holds the working tree; leaving it"
elif [[ -d /srv/faramir ]]; then
  sudo tar czf "/srv/faramir.bak-${STAMP}.tgz" -C /srv faramir
  sudo rm -rf /srv/faramir
  say "     archived to /srv/faramir.bak-${STAMP}.tgz, then removed"
else
  skip "/srv/faramir is gone"
fi

# --------------------------------------------------------------------------
say "4/6  ansible-vault -> sops"
cd "$WORKTREE"
if [[ -f $SOPS_FILE ]]; then
  skip "${SOPS_FILE} exists"
elif [[ ! -f $VAULT ]]; then
  skip "no ${VAULT} to migrate"
else
  mkdir -p "$(dirname "$SOPS_FILE")"
  # Additive: this reads the vault and writes the sops file, and removes
  # nothing.  Deleting the vault is a decision for after a real playbook run.
  "${HERE}/migrate-vault.sh" "$VAULT" "$SOPS_FILE"
fi

# --------------------------------------------------------------------------
say "5/6  var names -> the environment"
# vars.yml sorts before vault.yml, so ansible keeps using the vault until that
# file is removed: writing this changes nothing on its own.
if [[ -f $VARS_FILE ]] && grep -q "lookup('env'" "$VARS_FILE" 2>/dev/null; then
  skip "${VARS_FILE} already maps names to the environment"
elif [[ ! -f $SOPS_FILE ]]; then
  skip "no ${SOPS_FILE} yet; nothing to map"
else
  mkdir -p "$(dirname "$VARS_FILE")"
  # Top-level "key:" lines only, and the whole key.  A trailing [0-9] or an
  # upper-case letter is part of the name: truncating "router_pw2" to
  # "router_pw" writes a mapping for a name that does not exist and drops the
  # one that does, and the playbook then resolves it to empty.
  #
  # Written to a temporary file and moved into place: the redirection would
  # otherwise truncate VARS_FILE before sops ran, and a sops failure under
  # pipefail would leave it empty.
  tmp="$(mktemp "${VARS_FILE}.XXXXXX")"
  if ! sops -d "$SOPS_FILE" |
       grep -oE '^[A-Za-z_][A-Za-z0-9_]*:' |
       tr -d ':' |
       while read -r name; do
         printf '%s: "{{ lookup('"'"'env'"'"', '"'"'%s'"'"') }}"\n' "$name" "$name"
       done >"$tmp"; then
    rm -f "$tmp"
    die "could not read ${SOPS_FILE}; ${VARS_FILE} left alone"
  fi
  mv "$tmp" "$VARS_FILE"
  say "     wrote ${VARS_FILE} ($(wc -l <"$VARS_FILE") names)"
fi

# --------------------------------------------------------------------------
say "6/6  restart the broker and see what it loaded"
# Restart, not reload.  SIGHUP re-fetches the value set using the config the
# process already has in memory; it does not re-read config.toml.  Step 1 is a
# config change, so a reload here reports the old paths and looks like the
# migration silently did nothing.
#
# Both services, not just the broker.  Each reads [secrets] files at startup and
# holds it in memory, so a broker restarted on its own asks a keeper that is
# still looking at the old path, and the error then names a file nobody
# configured any more.
sudo systemctl restart faramir-keeper faramir-broker
sleep 1
status="$(faramir status 2>&1 || true)"
refs="$(printf '%s' "$status" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secrets"]["ref_count"])' 2>/dev/null || echo 0)"
printf '%s\n' "$status" | sed 's/^/     /'

if [[ ${refs:-0} -gt 0 ]]; then
  say "loaded ${refs} refs.  Migration done."
else
  say "loaded 0 refs.  Everything above succeeded, but the broker is protecting"
  say "nothing until a sops file it can read exists at [secrets] files."
fi

cat <<EOF

Still yours to do, both deliberately left out:

  1. Prove a brokered run resolves a var end to end, then remove the vault:
       faramir run --env-file faramir.env -- \\
           ansible tron -m debug -a 'var=<one of the names>'
       git rm ${VAULT} && sed -i '/^vault_password_file/d' ansible.cfg

  2. Retire the old account once nothing points at its home.  In the
     ansible-ctrl checkout:
       make faramir_cleanup ARGS="-e faramir_cleanup_remove_account=true \\
                                  -e faramir_cleanup_remove_home=true"

  3. Restart your Claude session so the merged hook is read, then:
       sudo tests/verify.sh
EOF

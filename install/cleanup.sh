#!/usr/bin/env bash
# Remove what earlier layouts of this project left behind.  Not a numbered
# phase: run it by hand, after an upgrade, as root.
#
# Reports by default and changes nothing.  Pass --apply to act.
#
# It never touches the config directory or the store.  The age key and the
# managed sops files are the one thing a cleanup script must not decide about:
# deleting the key makes every sops file unreadable, retroactively.  Removing the
# broker is install/uninstall.sh, which refuses the same things.
#
# Accounts and groups are reported, never removed, unless --remove-accounts is
# given as well, and then only when the broker is not installed and the account
# owns nothing outside its own home.  A uid that still owns files is not
# reclaimable by deleting it; the files are left orphaned and the next account
# to take that uid inherits them.
set -euo pipefail

APPLY=0

# Where this install put them, so what is reported names the paths a reader
# will actually find.  Give these the values the install was given.
CONFIG_DIR="${CONFIG_DIR:-/etc/faramir}"
SECRETS_DIR="${SECRETS_DIR:-/etc/faramir/secrets}"
REMOVE_ACCOUNTS=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --remove-accounts) REMOVE_ACCOUNTS=1 ;;
    -h|--help)
      sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
      echo
      echo "usage: cleanup.sh [--apply] [--remove-accounts]"
      exit 0
      ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

OPERATOR="${OPERATOR:-${SUDO_USER:-}}"
[[ -n $OPERATOR && $OPERATOR != root ]] || {
  echo "set OPERATOR to the account the coding agent runs as" >&2; exit 1; }
OPERATOR_HOME="$(getent passwd "$OPERATOR" | cut -d: -f6)" || OPERATOR_HOME=""
[[ -n $OPERATOR_HOME ]] || { echo "no such user: $OPERATOR" >&2; exit 1; }

GROUP="${DEV_GROUP:-dev}"
BROKER_BIN="${BROKER_BIN:-/usr/local/bin/faramir-broker}"
FOUND=0

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }

# act <description> <command...>
act() {
  local what="$1"; shift
  FOUND=1
  if [[ $APPLY -eq 1 ]]; then
    say "removing: ${what}"
    "$@"
  else
    say "would remove: ${what}"
  fi
}

say "cleanup for ${OPERATOR} (${OPERATOR_HOME})"
[[ $APPLY -eq 1 ]] || note "dry run; pass --apply to make these changes"
echo

# -- the account-wide hook --------------------------------------------------
#
# The hook used to be registered in the operator's own settings, where it
# covered every project.  It is per project now, because registering it is what
# auto-approves Bash: a rewritten command matches no permission rule.  Left in
# the home it silently keeps that cost everywhere, including in repositories
# that were never enrolled and get nothing back for it.
SETTINGS="${OPERATOR_HOME}/.claude/settings.json"
if [[ -f $SETTINGS ]] && grep -q faramir-guard "$SETTINGS"; then
  if ! command -v python3 >/dev/null 2>&1; then
    say "FOUND: ${SETTINGS} registers faramir-guard account-wide"
    note "python3 is missing, so this cannot be edited here."
    note "Remove the PreToolUse block naming faramir-guard by hand."
    FOUND=1
  else
    act "the account-wide faramir-guard hook in ${SETTINGS}" \
      python3 - "$SETTINGS" <<'PYEOF'
import json, shutil, sys

path = sys.argv[1]
shutil.copy2(path, path + ".bak")
with open(path) as fh:
    settings = json.load(fh)

hooks = settings.get("hooks", {})
kept_events = {}
for event, matchers in hooks.items():
    kept_matchers = []
    for matcher in matchers:
        entries = [h for h in matcher.get("hooks", [])
                   if "faramir-guard" not in str(h.get("command", ""))]
        if entries:
            kept_matchers.append({**matcher, "hooks": entries})
    if kept_matchers:
        kept_events[event] = kept_matchers

# Drop the containers too when nothing else used them, rather than leaving an
# empty "hooks": {} that reads as a configuration someone chose.
if kept_events:
    settings["hooks"] = kept_events
else:
    settings.pop("hooks", None)

with open(path, "w") as fh:
    json.dump(settings, fh, indent=2)
    fh.write("\n")
print(f"    edited {path}, previous copy at {path}.bak")
PYEOF
  fi
fi

# -- leftovers a phase wrote beside a file it would not overwrite ------------
for leftover in "${OPERATOR_HOME}/.claude/settings.json.dist" \
                "${OPERATOR_HOME}/.claude/settings.local.json.dist"; do
  [[ -f $leftover ]] && act "$leftover" rm -f "$leftover"
done

# -- the old default working tree -------------------------------------------
#
# Only when empty.  This used to be created by phase 1 whether or not anyone
# wanted it, so an empty one is an artefact; a populated one is somebody's work.
for tree in /srv/faramir/worktree /srv/faramir; do
  if [[ -d $tree ]]; then
    if [[ -z $(ls -A "$tree" 2>/dev/null) ]]; then
      act "empty ${tree}" rmdir "$tree"
    else
      say "KEEPING: ${tree} is not empty"
      note "$(find "$tree" -maxdepth 1 -mindepth 1 | wc -l) entries; remove it yourself if it is dead"
      FOUND=1
    fi
  fi
done

# -- accounts ---------------------------------------------------------------
#
# Reported, and only removed with --remove-accounts and an uninstalled broker.
SERVICE_USERS=("${BROKER_USER:-faramir-broker}" "${KEEPER_USER:-faramir-keeper}" "${EXEC_USER:-faramir-exec}")

if [[ -x $BROKER_BIN ]]; then
  if [[ $REMOVE_ACCOUNTS -eq 1 ]]; then
    say "KEEPING the service accounts: ${BROKER_BIN} is installed"
    note "run install/uninstall.sh first if you meant to remove the broker"
  fi
else
  for u in "${SERVICE_USERS[@]}"; do
    id -u "$u" >/dev/null 2>&1 || continue
    home="$(getent passwd "$u" | cut -d: -f6)"
    # A uid owning files elsewhere cannot be reclaimed by deleting it: the
    # files stay, and whoever next gets that uid inherits them.
    stray="$(find / -xdev -user "$u" -not -path "${home}/*" -not -path "$home" -print -quit 2>/dev/null || true)"
    if [[ -n $stray ]]; then
      say "KEEPING ${u}: it still owns files outside ${home}"
      note "first one: ${stray}"
      FOUND=1
    elif [[ $REMOVE_ACCOUNTS -eq 1 ]]; then
      act "account ${u} and ${home}" userdel -r "$u"
    else
      say "STALE: account ${u} (broker not installed, owns nothing outside ${home})"
      note "pass --remove-accounts to delete it and its home"
      FOUND=1
    fi
  done
fi

# -- the group --------------------------------------------------------------
#
# Named rather than removed while anything is still in it.  Membership grants
# read on the store, so a member nobody recognises is worth a look
# even when it is not this project's to delete.
if getent group "$GROUP" >/dev/null; then
  members="$(getent group "$GROUP" | cut -d: -f4)"
  outsiders=""
  IFS=',' read -ra current <<<"$members"
  for m in "${current[@]}"; do
    [[ -z $m ]] && continue
    [[ $m == "$OPERATOR" ]] && continue
    for known in "${SERVICE_USERS[@]}"; do
      [[ $m == "$known" ]] && continue 2
    done
    outsiders+="${outsiders:+ }${m}"
  done
  if [[ -n $outsiders ]]; then
    say "REVIEW: ${GROUP} has members this project did not create: ${outsiders}"
    note "membership grants read on ${SECRETS_DIR}, so a dead account"
    note "here is a standing grant.  Check each one is still in use, then:"
    for m in $outsiders; do note "  gpasswd -d ${m} ${GROUP}"; done
    FOUND=1
  fi
fi

echo
if [[ $FOUND -eq 0 ]]; then
  say "nothing to clean"
elif [[ $APPLY -eq 1 ]]; then
  say "done.  ${CONFIG_DIR} and ${SECRETS_DIR} were not touched."
else
  say "nothing changed.  Re-run with --apply."
fi

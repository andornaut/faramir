#!/usr/bin/env bash
# Phase 3 -- install the broker binaries, config and systemd units.
#
# Idempotent: safe to re-run after rebuilding.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BROKER_USER="${BROKER_USER:-faramir-broker}"
OPERATOR="${OPERATOR:-${SUDO_USER:-$(id -un)}}"
GROUP="${DEV_GROUP:-dev}"
BIN="${FARAMIR_BIN:-$REPO/bin}"
# The base configuration.  Settings belonging to a consumer of the broker go in
# /etc/faramir/config.d/*.toml instead, which merge over whatever is installed
# here and survive a config this script declines to overwrite.
# A relative path resolves against the repo, so the documented invocation works
# from any directory.
CONFIG="${CONFIG:-etc/config.toml}"
[[ $CONFIG = /* ]] || CONFIG="$REPO/$CONFIG"
# Where the base config and its drop-ins are installed.  /etc by default, which
# is where a system daemon's configuration belongs and where three uids can read
# it without any of them owning it.  A consumer that keeps its configuration
# elsewhere sets this, and the units are given FARAMIR_CONFIG to match.
#
# What the daemons can see decides this, not what the modes say: each unit is
# sandboxed, so a readable directory can still be invisible inside one.  The
# checks below reject the placements that do not work and the drop-in further
# down opens up the one that does.
CONFIG_DIR="${CONFIG_DIR:-/etc/faramir}"
[[ $CONFIG_DIR = /* ]] || { echo "CONFIG_DIR must be absolute: $CONFIG_DIR" >&2; exit 1; }
# systemd word-splits Environment= and expands % specifiers in it, so a path
# holding either reaches the daemons truncated or not at all.
[[ $CONFIG_DIR != *[[:space:]]* ]] ||
  { echo "CONFIG_DIR must not contain whitespace: $CONFIG_DIR" >&2; exit 1; }
[[ $CONFIG_DIR != *%* ]] ||
  { echo "CONFIG_DIR must not contain '%': $CONFIG_DIR" >&2; exit 1; }
# Every unit sets PrivateTmp=true, which gives each its own /tmp and /var/tmp.
case $CONFIG_DIR in
  /tmp/*|/var/tmp/*)
    echo "CONFIG_DIR cannot be under /tmp or /var/tmp: PrivateTmp=true gives" >&2
    echo "each unit a private one, so nothing there is the file you installed" >&2
    exit 1
    ;;
esac
CONFIG_FILE="$CONFIG_DIR/config.toml"

# The home CONFIG_DIR sits in, or empty when it sits outside every home.  A
# config inside one needs the keeper's ProtectHome= relaxed, which is the drop-in
# written further down.
home_of() {
  case "$1" in
    /root|/root/*) echo /root ;;
    /home/*) local rest="${1#/home/}"; echo "/home/${rest%%/*}" ;;
    *) echo "" ;;
  esac
}
CONFIG_HOME="$(home_of "$CONFIG_DIR")"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
# Before anything is installed: a typo here would otherwise surface as a bare
# "cannot stat" once the binaries and hook are already on the host.
[[ -f $CONFIG ]] || { echo "no such config: $CONFIG" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

# A mounted filesystem sits on a different device from the directory it covers.
# stat rather than mountpoint(1), which is not on every host and whose absence
# would read here as "not mounted".
is_mounted() {
  [[ -d $1 ]] && [[ "$(stat -c %d "$1")" != "$(stat -c %d "$1/..")" ]]
}

# An encrypted home is a different directory before its owner logs in, and
# writing to it then lands in the unencrypted backing store, where it is
# shadowed and invisible the moment the home mounts.  The install would look
# like it worked and the daemons would never see the file again.
if [[ -n $CONFIG_HOME ]] &&
   { [[ -d /home/.ecryptfs/${CONFIG_HOME##*/} ]] || [[ -e ${CONFIG_HOME}/.ecryptfs ]]; } &&
   ! is_mounted "$CONFIG_HOME"; then
  echo "${CONFIG_HOME} is an encrypted home and is not mounted." >&2
  echo "Installing into it now would write plaintext to the backing store," >&2
  echo "where it is hidden once the home mounts.  Log in as its owner first." >&2
  exit 1
fi

# The binaries are built ahead of time, so this script needs no toolchain and
# no interpreter on the target host.  Build them with `make build` first.
say "checking for built binaries in ${BIN}"
missing=()
for b in faramir faramir-broker faramir-keeper faramir-exec faramir-mcp faramir-guard; do
  [[ -x "$BIN/$b" ]] || missing+=("$b")
done
if ((${#missing[@]})); then
  echo "not built: ${missing[*]}" >&2
  echo "run 'make build' (needs Go), or set FARAMIR_BIN to a directory holding them" >&2
  exit 1
fi

say "binaries -> /usr/local/bin"
for b in faramir faramir-broker faramir-keeper faramir-exec faramir-mcp; do
  install -m 0755 "$BIN/$b" "/usr/local/bin/$b"
done
say "hook -> /usr/local/libexec/faramir"
install -d -m 0755 /usr/local/libexec/faramir
install -m 0755 "$BIN/faramir-guard" /usr/local/libexec/faramir/faramir-guard
# Next to the hook rather than under /etc/faramir, so it travels with the thing
# that reads it.  A patterns file the hook cannot read is worse than none: it
# falls back to a built-in list that is silently weaker.
install -m 0644 "$REPO/agent/hooks/deny-patterns.txt" /usr/local/libexec/faramir/deny-patterns.txt
# Sourced by the shell the hook rewrites into, so it is read, never executed.
install -m 0644 "$REPO/agent/hooks/wrap.sh" /usr/local/libexec/faramir/wrap.sh

say "docs -> /usr/local/share/doc/faramir"
install -d -m 0755 /usr/local/share/doc/faramir
install -m 0644 "$REPO/README.md" /usr/local/share/doc/faramir/README.md
install -m 0644 "$REPO"/docs/*.md /usr/local/share/doc/faramir/

# Three services read config.toml from here, so under /etc the directory belongs
# to none of them.  The age key is protected by its own mode, not by this one.
# config.d holds the settings belonging to whatever consumes the broker rather
# than to the broker: which sops files to manage, which SSH key to lend.  World
# readable like the config beside it, and holding no value either.
#
# Created only when absent.  install -d applies -m/-o/-g to a directory that is
# already there, so an unconditional call would re-mode and re-own one the
# operator had set up: a CONFIG_DIR inside their own home would come back
# root-owned and no longer theirs to edit.
CONFIG_OWNER=root
CONFIG_GROUP=root
if [[ -n $CONFIG_HOME ]]; then
  # Inside a home, its owner keeps it, so they edit their own config without
  # sudo.  The daemons only ever read it.
  CONFIG_OWNER="$(stat -c %U "$CONFIG_HOME")"
  CONFIG_GROUP="$(stat -c %G "$CONFIG_HOME")"
fi
for dir in "$CONFIG_DIR" "$CONFIG_DIR/config.d"; do
  [[ -d $dir ]] || install -d -m 0755 -o "$CONFIG_OWNER" -g "$CONFIG_GROUP" "$dir"
done
install -d -m 0750 -o "$BROKER_USER" -g "$BROKER_USER" /var/log/faramir

# Configs are installed verbatim.  Every path in one is absolute and the units
# name no tree, so there is nothing to substitute and no placeholder that can
# survive into a running config.
install_config() {
  # Written to a temporary file and moved into place, never redirected onto the
  # destination: a failed copy would otherwise leave an empty config behind,
  # and every later run would take the "keeping existing" branch and preserve
  # it forever.
  local src="$1" dst="$2" tmp
  tmp="$(mktemp "${dst}.XXXXXX")"
  if ! cat "$src" >"$tmp"; then
    rm -f "$tmp"; return 1
  fi
  # The same owner as the directory it lands in, so a config in a home is the
  # operator's to edit.  Owning the directory alone is not enough: an editor
  # that writes in place rather than renaming still needs the file.
  chown "$CONFIG_OWNER:$CONFIG_GROUP" "$tmp"
  chmod 0644 "$tmp"
  mv "$tmp" "$dst"
}

# Reading a config needs the broker's own parser: quoting styles and trailing
# comments have to be read the way the broker reads them, or a config that is
# perfectly correct is refused by a check of its own.
config_parses() {
  "$BIN/faramir-broker" -c "$1" --parse-only 2>/dev/null
}

# Before anything is written to the host: a CONFIG that does not parse should
# abort here, not halfway through.
config_parses "$CONFIG" || {
  say "cannot read ${CONFIG}: it does not parse as a faramir config"
  exit 1
}

if [[ -f $CONFIG_FILE ]]; then
  say "keeping existing ${CONFIG_FILE} (new default at config.toml.dist)"
  install_config "$CONFIG" "$CONFIG_FILE.dist" || exit 1
  if ! config_parses "$CONFIG_FILE"; then
    say "WARNING: the installed config does not parse; the broker will not"
    say "         start until it does.  The error above names the file, which"
    say "         may be a drop-in under ${CONFIG_DIR}/config.d rather than"
    say "         config.toml itself."
  fi
else
  say "config ${CONFIG#"$REPO"/} -> ${CONFIG_FILE}"
  install_config "$CONFIG" "$CONFIG_FILE" || exit 1
fi

say "systemd units"
for unit in faramir-broker.socket faramir-broker.service \
            faramir-keeper.socket faramir-keeper.service \
            faramir-exec.socket faramir-exec.service; do
  install -m 0644 "$REPO/systemd/${unit}" "/etc/systemd/system/${unit}"
done

# The daemons fall back to the compiled-in /etc/faramir/config.toml when nothing
# names one, so a CONFIG_DIR elsewhere has to reach them.  Written as a drop-in
# rather than by rewriting ExecStart: an ExecStart= reset that goes wrong leaves
# a unit with no command at all, and the config path is the only thing changing.
# Removed when CONFIG_DIR is the default, so the units fall back to their own
# built-in path and nothing points them anywhere else.
for unit in faramir-broker faramir-keeper faramir-exec; do
  dropin="/etc/systemd/system/${unit}.service.d/config-path.conf"
  if [[ $CONFIG_DIR = /etc/faramir ]]; then
    rm -f "$dropin"
    continue
  fi
  install -d -m 0755 -o root -g root "$(dirname "$dropin")"
  cat > "$dropin" <<EOF
# Installed by faramir: CONFIG_DIR was ${CONFIG_DIR}.
[Service]
Environment=FARAMIR_CONFIG=${CONFIG_FILE}
EOF
  # The keeper's shipped unit sets ProtectHome=true, so a config inside a home
  # is not merely unreadable there, it is absent: the unit would start, find
  # nothing, and hold no values.  tmpfs keeps every other home hidden and binds
  # back only the directory the config is in.  No leading "-", so a config that
  # is not there stops the keeper rather than leaving it up holding nothing.
  #
  # A [secrets] file outside CONFIG_DIR needs its own BindReadOnlyPaths= line;
  # this script never reads the config, so it cannot know about one.
  if [[ $unit = faramir-keeper && -n $CONFIG_HOME ]]; then
    cat >> "$dropin" <<EOF
ProtectHome=tmpfs
BindReadOnlyPaths=${CONFIG_DIR}
EOF
  fi
  chmod 0644 "$dropin"
done

# /run/faramir belongs to tmpfiles, not to a RuntimeDirectory= on any unit:
# systemd chowns a RuntimeDirectory recursively and would rewrite the ownership
# systemd itself gave the sockets in it.  See the file's own comment.
install -m 0644 "$REPO/systemd/faramir.tmpfiles.conf" /etc/tmpfiles.d/faramir.conf

# Nothing here names a working tree.  The keeper and the broker read the sops
# files from wherever the config points, and only the executor touches a tree at
# all, because a brokered command runs where its caller was.  It is granted
# /home, which covers where callers work, with modes deciding what it can write.
# A caller working outside /home needs a drop-in extending ReadWritePaths= on
# faramir-exec.service.

# systemd may not be running (container, chroot, image build).  Install the
# units anyway; just do not pretend to have started anything.
if systemctl is-system-running --quiet 2>/dev/null || [[ -d /run/systemd/system ]]; then
  HAVE_SYSTEMD=1
  systemctl daemon-reload
  systemd-tmpfiles --create /etc/tmpfiles.d/faramir.conf
else
  HAVE_SYSTEMD=0
  say "systemd is not running here; units installed but not started"
fi

if [[ $HAVE_SYSTEMD -eq 1 && -f /etc/faramir/age.key ]]; then
  # Nothing in this block is fatal, under set -e or otherwise: a unit that will
  # not start is exactly when the --check gate below and systemd-analyze have
  # something to say, and aborting here would replace their output with a raw
  # systemctl error.
  #
  # The keeper and the executor first: the broker talks to both.
  systemctl enable --now \
    faramir-keeper.socket faramir-exec.socket faramir-broker.socket || true
  # Restart, not just enable --now: an already-active socket keeps whatever
  # ownership its file was left with, and the services below have to pick up
  # the new listeners anyway.
  systemctl restart \
    faramir-keeper.socket faramir-exec.socket faramir-broker.socket || true
  for unit in faramir-keeper faramir-exec faramir-broker; do
    systemctl restart "${unit}.service" || true
  done
  for unit in faramir-keeper.service faramir-exec.service faramir-broker.service; do
    say "systemd-analyze security ${unit}"
    systemd-analyze security "$unit" || true
  done
elif [[ ! -f /etc/faramir/age.key ]]; then
  say "NOT starting faramir: /etc/faramir/age.key is missing."
  say "Run install/20-sops-init.sh first, then:"
  say "  systemctl enable --now faramir-keeper.socket faramir-exec.socket faramir-broker.socket"
fi

say "validating the installed config as ${BROKER_USER}"
# As the broker's own uid, not root: --check opens the SSH keys and the secrets
# files itself, and root reads what the broker cannot.  A key left root:root
# would otherwise pass here and leave every brokered command unable to
# authenticate against any host.
runuser -u "$BROKER_USER" -- \
  /usr/local/bin/faramir-broker -c "$CONFIG_FILE" --check || {
  say "validation FAILED -- fix ${CONFIG_FILE} before enabling the unit."
  say "A [secrets] file the gate names is one the broker could not load, and a"
  say "file that is not there counts: create the store first, then re-run this."
  say "A ref reported under not_redactable needs lengthening instead."
  exit 1
}

cat <<EOF

Phase 3 acceptance (run these):
  cat /proc/\$(pgrep -u ${BROKER_USER} -f faramir-broker | head -1)/environ
      -> No such file or directory   (ProtectProc=invisible)
  test -w /run/faramir/broker.sock && echo writable
      -> writable                    (group ${GROUP} access works)
EOF

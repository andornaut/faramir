#!/bin/bash
# Driver for the end-to-end suites. Run from this directory.
#
#   ./e2e.sh fetch         download the third-party binaries the image installs
#   ./e2e.sh up            build the binary and image, start the container, bootstrap
#   ./e2e.sh run NAME...   copy in and run check-NAME.sh (default: every suite)
#   ./e2e.sh sh [cmd...]   a shell in the container, or one command
#   ./e2e.sh cp FILE...    copy a script in without running it
#   ./e2e.sh down          remove the container and image
#   ./e2e.sh both          a stack per sudo implementation, at the same time
#
# SUDO=sudo (the default) or SUDO=sudo-rs picks which sudo the stack's host runs,
# and so which arrangement `--allow-sudo` installs. Every container, image and
# network name takes a suffix from it, so the two stacks are separate and can be
# up together; `both` is that pair run concurrently.
#
# `up` is safe to re-run: it rebuilds the binary from the current tree and
# re-bootstraps, which is idempotent.
#
# `run` is single-shot. The suites mutate the shared install (secrets are
# rotated, a sudo grant is installed, the last suite uninstalls the host), so a
# second `run` without `up` measures the leftovers of the first and reports
# failures that are not regressions. `run` warns when the box is already dirty;
# `up` is the clean baseline.
#
# Naming suites is the same hazard from the other side: each leaves what the
# later ones examine, so a set that is not a prefix of SUITES is measured against
# a box its predecessors never set up. `run` warns about that too, and the way
# back from either is `up` and then a whole run.
#
# sops, age and age-keygen must be present beside this script: the image has no
# network, so they are copied into the build context rather than fetched inside
# it. `fetch` puts them there. See README.md.
set -eu

# Which sudo this stack's host runs, and so which arrangement `--allow-sudo`
# installs: the two implementations take different settings out of the same
# /etc/sudoers.d, and the one most Ubuntu hosts now have is sudo-rs. Both are in
# the image; this picks the `sudo` alternatives group inside the container.
#
# Every name below takes a suffix from it, so `SUDO=sudo-rs ./e2e.sh up` builds
# a stack of its own and the two run side by side. Unset is the original sudo
# and the unsuffixed names, so a command that does not ask for an arrangement
# uses the one the image pins.
#
# The values are the two implementations' own names rather than labels for
# them, so what a CI job is called, what an operator types and what the docs
# say are one word.
SUDO=${SUDO:-sudo}
case $SUDO in
  sudo)    SUFFIX= ;;
  sudo-rs) SUFFIX=-rs ;;
  *) echo "e2e: SUDO is '$SUDO', want 'sudo' or 'sudo-rs'" >&2; exit 2 ;;
esac
NAME=${NAME:-faramir-e2e$SUFFIX}
IMAGE=${IMAGE:-faramir-e2e$SUFFIX}
# A second host the broker's key is the only way into, on a network of their
# own, so the ssh suite can put the relay to a real sshd rather than to a stub.
MANAGED=${MANAGED:-managed-host$SUFFIX}
# What the suites dial it by, which is NOT the container name: the two stacks are
# on networks of their own, so both can answer to the same alias, and a suite
# that hardcodes it works in either.
MANAGED_HOST=managed-host
MANAGED_IMAGE=${MANAGED_IMAGE:-faramir-managed$SUFFIX}
NETWORK=${NETWORK:-faramirnet$SUFFIX}
HERE=$(cd "$(dirname "$0")" && pwd)
# The tree under test, two levels up from tests/e2e.
REPO=${REPO:-$(cd "$HERE/../.." && pwd)}
SUITES=(init project config disclose plugin guard wrap leak stream exec logs ssh doctor escalation secrets link block uninstall)

# The third-party binaries the image installs, pinned by version and by digest.
# Upstream's own builds, which are static, so the image needs no libc to match.
#
# The digest is the point rather than a formality: these are what the suites
# decrypt and generate keys with, so a run that says a release is fit to ship
# says it about a tool named here. Bumping one means changing its digest too,
# which `fetch` prints when it refuses.
SOPS_VERSION=3.13.3
SOPS_SHA256=e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b
AGE_VERSION=1.1.1
AGE_SHA256=0c6ddc31c276f55e9414fe27af4aada4579ce2fb824c1ec3f207873a77a49752
AGE_KEYGEN_SHA256=e279f64ccd11347e57b8d28304e3e358ae1a5ef4f19107e7a1f9c9156fdcad91

die() { printf 'e2e: %s\n' "$1" >&2; exit 1; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = true ]; }

# build_skew produces a second binary reporting a version the first one does
# not, which is what the doctor suite swaps in to make the broker and the CLI
# disagree. The version is a linker variable, so a stamp is the whole job and
# the tree is never edited to build it.
build_skew() {
  ( cd "$REPO" && go build \
      -ldflags "-X github.com/andornaut/faramir/internal/version.Version=9.9.9" \
      -o "$HERE/faramir-skew" ./cmd/faramir )
  # A -X naming a symbol that moved does nothing and exits 0, which would leave
  # the doctor suite comparing a binary against itself and passing on nothing.
  "$HERE/faramir-skew" --version | grep -q '9\.9\.9' ||
    die "the version stamp did not take: build_skew names the wrong symbol"
}

# digest_of is the sha256 of a file, or empty where there is none.
digest_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# pinned_digest is what the file beside this script is pinned to, by name.
pinned_digest() {
  case "$1" in
    sops) printf '%s' "$SOPS_SHA256";;
    age) printf '%s' "$AGE_SHA256";;
    age-keygen) printf '%s' "$AGE_KEYGEN_SHA256";;
  esac
}

# pins_apply reports whether the digests above describe this machine's binaries.
# They name one architecture's builds, so on any other the operator supplies the
# three by hand and there is nothing here to check them against.
pins_apply() { [ "$(uname -m)" = x86_64 ]; }

# verified puts a downloaded file in place, and only the one pinned above. A
# digest that does not match is a different binary whatever the reason, and the
# rig that decides whether a secrets broker ships is not where to find out which.
verified() { # src, dest, sha256
  local got
  got=$(digest_of "$1")
  [ "$got" = "$3" ] || die "$(basename "$2") hashes to $got, not the pinned $3; refusing it"
  install -m 0755 "$1" "$2"
}

# check_pinned holds a file that is already here to the same digest a download
# would have been held to. Without it the pin covers only the run that fetched:
# a version bump would leave the old binary in place, `fetch` would report it as
# already here, and the image would be built from a tool the pin says was not
# used.
check_pinned() { # name
  pins_apply || return 0
  local got want
  got=$(digest_of "$HERE/$1")
  want=$(pinned_digest "$1")
  [ "$got" = "$want" ] && return 0
  die "$1 beside this script hashes to $got, not the pinned $want. Delete it and run ./e2e.sh fetch to take the pinned build, or change the pin if this one is meant to be it"
}

# needs_download lists which of the three are not here yet.
needs_download() {
  local out=""
  for tool in sops age age-keygen; do
    [ -f "$HERE/$tool" ] || out="$out $tool"
  done
  printf '%s' "$out"
}

# cmd_fetch downloads what `up` refuses to build without. What is already
# beside the script is checked against the pin rather than downloaded again, so
# this is safe to run before every up; delete a file to replace it, which is
# also how a version bump is applied.
# fetch_to downloads one file, retrying a connection that fails part way.
#
# The digest below is what says the bytes are right, so a retry cannot smuggle
# anything in: what it buys is a run that survives one reset from a release
# host, which is not a fault in this tree and used to fail the whole job.
# --retry-all-errors so a 5xx is retried as well as a dropped connection, and
# -C - so a partial file resumes rather than starting again.
fetch_to() {
  curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors -C - -o "$1" "$2"
}

cmd_fetch() {
  local missing
  missing=$(needs_download)
  if [ -z "$missing" ]; then
    for tool in sops age age-keygen; do check_pinned "$tool"; done
    echo "== sops, age and age-keygen are already here$(pins_apply && echo ", and match the pin")"
    return
  fi
  # Only what actually downloads needs these, so a box that was given the three
  # by hand can still run the suites without curl, and on an architecture these
  # digests do not describe.
  pins_apply || die "these digests are x86_64 builds and this is $(uname -m); copy$missing in beside this script by hand"
  for tool in curl tar sha256sum install; do
    command -v $tool >/dev/null || die "$tool is needed to download$missing, and is not installed"
  done
  local work
  work=$(mktemp -d)
  # EXIT rather than RETURN: every refusal below leaves through die, which exits
  # rather than returning, and a RETURN trap does not run on the way out.
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT

  if [ -f "$HERE/sops" ]; then
    check_pinned sops
  else
    echo "== fetching sops $SOPS_VERSION"
    fetch_to "$work/sops" \
      "https://github.com/getsops/sops/releases/download/v$SOPS_VERSION/sops-v$SOPS_VERSION.linux.amd64" \
      || die "could not download sops $SOPS_VERSION"
    verified "$work/sops" "$HERE/sops" "$SOPS_SHA256"
  fi

  if [ -f "$HERE/age" ] && [ -f "$HERE/age-keygen" ]; then
    check_pinned age
    check_pinned age-keygen
    return
  fi
  echo "== fetching age $AGE_VERSION"
  # One archive carries both, so both are taken from it rather than one being
  # left at whatever version was already here.
  fetch_to "$work/age.tgz" \
    "https://github.com/FiloSottile/age/releases/download/v$AGE_VERSION/age-v$AGE_VERSION-linux-amd64.tar.gz" \
    || die "could not download age $AGE_VERSION"
  tar -xzf "$work/age.tgz" -C "$work" || die "the age archive would not extract"
  verified "$work/age/age" "$HERE/age" "$AGE_SHA256"
  verified "$work/age/age-keygen" "$HERE/age-keygen" "$AGE_KEYGEN_SHA256"
}

cmd_up() {
  echo "== building the binary from $REPO"
  ( cd "$REPO" && go build -o "$HERE/faramir" ./cmd/faramir )
  build_skew
  # Checked here as well as in fetch, this being what decides what goes into the
  # image: `up` can be run on its own, and a tool nobody can name again makes a
  # passing run unrepeatable.
  for tool in sops age age-keygen; do
    [ -f "$HERE/$tool" ] || die "$tool is missing from the build context; run ./e2e.sh fetch, or copy it in beside this script"
    check_pinned "$tool"
  done
  echo "== building the image"
  docker build -q -f "$HERE/Dockerfile.e2e" -t "$IMAGE" "$HERE" >/dev/null
  echo "== building the managed host image"
  docker build -q -f "$HERE/Dockerfile.managed" -t "$MANAGED_IMAGE" "$HERE" >/dev/null
  docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK" >/dev/null
  echo "== starting the containers"
  docker rm -f "$NAME" "$MANAGED" >/dev/null 2>&1 || true
  # --network-alias, so the broker dials the name the suite and the known_hosts
  # entry both use.
  docker run -d --name "$MANAGED" --network "$NETWORK" --network-alias "$MANAGED_HOST" \
    "$MANAGED_IMAGE" >/dev/null
  # Privileged with the host's cgroup namespace: systemd inside a container
  # needs a writable cgroup tree, and a private namespace leaves it exiting 255.
  #
  # Capped well above what the suites need. A brokered command that runs away is
  # a fault this is here to find, and without a limit the container has the whole
  # machine to take with it: the kernel's OOM killer then chooses among every
  # process on the host rather than among the ones in here.
  docker run -d --name "$NAME" --privileged --cgroupns=host --network "$NETWORK" \
    --memory 4g --memory-swap 4g \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw "$IMAGE" >/dev/null
  for _ in $(seq 30); do
    [ "$(docker exec "$NAME" systemctl is-system-running 2>/dev/null)" = running ] && break
    sleep 1
  done
  running || die "the container did not come up"
  echo "== bootstrapping"
  docker cp "$HERE/plugin-harness.mjs" "$NAME":/root/
  # Which sudo this stack's host runs. Set before bootstrap, `faramir init`
  # reading it to decide which arrangement the grant gets. The image installs
  # both and pins the original, so this is the only thing that moves it.
  case $SUDO in
    sudo)    docker exec "$NAME" update-alternatives --set sudo /usr/bin/sudo.ws >/dev/null ;;
    sudo-rs) docker exec "$NAME" update-alternatives --set sudo /usr/lib/cargo/bin/sudo >/dev/null ;;
  esac
  echo "== sudo is $(docker exec "$NAME" sudo -V 2>/dev/null | head -1)"
  docker cp "$HERE/bootstrap.sh" "$NAME":/root/
  docker exec "$NAME" bash /root/bootstrap.sh
  wire_managed_host
  # The marker cmd_run consumes to tell a first run on a clean box from a re-run
  # against one the suites have already mutated.
  docker exec "$NAME" touch /root/.e2e-fresh
}

# wire_managed_host is the part no container can do for itself: the broker's
# public key into the managed host's authorized_keys, and the managed host's
# host key into the file the executor verifies against. Both directions, or a
# brokered ssh fails and the suite cannot tell "the relay is broken" from "these
# two hosts were never introduced".
wire_managed_host() {
  echo "== introducing the broker and $MANAGED_HOST"
  for _ in $(seq 30); do
    docker exec "$MANAGED" test -f /etc/ssh/ssh_host_ed25519_key.pub && break
    sleep 1
  done
  local pub
  pub=$(docker exec "$NAME" cat /etc/faramir/id_ed25519.pub)
  docker exec "$MANAGED" bash -c "printf '%s\n' '$pub' > /home/deploy/.ssh/authorized_keys
    chown deploy:deploy /home/deploy/.ssh/authorized_keys
    chmod 0600 /home/deploy/.ssh/authorized_keys"
  # The system-wide file, which every account reads: the executor has no way to
  # be prompted to accept a key, so an unpinned host is refused before the
  # broker's key is offered.
  local hostkey
  hostkey=$(docker exec "$MANAGED" cat /etc/ssh/ssh_host_ed25519_key.pub)
  docker exec "$NAME" bash -c "printf '%s %s\n' '$MANAGED_HOST' '$(printf '%s' "$hostkey" | cut -d" " -f1,2)' \
    >> /etc/ssh/ssh_known_hosts; chmod 0644 /etc/ssh/ssh_known_hosts"
  docker exec "$NAME" sh -c "command -v ssh >/dev/null" \
    || echo "e2e: the broker image has no ssh client; the ssh suite will not run"
}

# cmd_both runs a stack per arrangement, at the same time. They share nothing:
# separate containers, images and network, and each container's systemd roots
# under its own docker-<id>.scope, so the cgroup trees do not meet.
cmd_both() {
  local status=0 pids=() arrangement
  # Under the invoking uid, /tmp being shared: another account's log of the same
  # name is one this cannot write and would report as an empty run.
  local logs
  logs="${TMPDIR:-/tmp}/faramir-e2e-$(id -u)"
  for arrangement in sudo sudo-rs; do
    ( SUDO=$arrangement "$0" fetch >/dev/null 2>&1
      SUDO=$arrangement "$0" up  >"$logs-$arrangement-up.log"  2>&1 &&
      SUDO=$arrangement "$0" run >"$logs-$arrangement-run.log" 2>&1 ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || status=1; done
  for arrangement in sudo sudo-rs; do
    printf '\n######## %s (%s-%s-run.log)\n' "$arrangement" "$logs" "$arrangement"
    grep -E "^(==|####|e2e:)" "$logs-$arrangement-run.log" 2>/dev/null ||
      { echo "  no run log; the stack did not come up"
        tail -5 "$logs-$arrangement-up.log" 2>/dev/null; }
  done
  [ $status -eq 0 ] && echo "e2e: both arrangements passed" || echo "e2e: an arrangement failed"
  return $status
}

cmd_cp() { for f in "$@"; do docker cp "$HERE/$f" "$NAME":/root/; done; }

cmd_run() {
  running || die "the container is not up; run ./e2e.sh up"
  # The suites are single-shot: they mutate the shared install, so a run against
  # a box a previous run already touched measures leftovers. `up` stamps a
  # marker; consume it on the first run and warn on every one after.
  if docker exec "$NAME" test -e /root/.e2e-fresh 2>/dev/null; then
    docker exec "$NAME" rm -f /root/.e2e-fresh
  else
    printf 'e2e: this box has already been run against; the suites have accumulated state.\n' >&2
    printf 'e2e: failures below may be leftovers, not regressions. Run ./e2e.sh up for a clean baseline.\n' >&2
  fi
  local names=("$@")
  [ ${#names[@]} -eq 0 ] && names=("${SUITES[@]}")
  # And the other way round: a suite whose predecessors have not run is measured
  # against a box they never set up. They share one install and each leaves what
  # the later ones examine -- check-project runs `init --agent claude`, which
  # writes the account-wide settings check-doctor then reports missing.
  #
  # A prefix of SUITES has every predecessor by construction, so `run init` and a
  # whole run say nothing; anything else is missing one.
  local prefix=1 i=0
  for n in "${names[@]}"; do
    [ "$n" = "${SUITES[$i]:-}" ] || { prefix=0; break; }
    i=$((i + 1))
  done
  if [ $prefix -eq 0 ]; then
    printf 'e2e: %d of %d suites, and not the first %d: the ones before them have not run.\n' \
      "${#names[@]}" "${#SUITES[@]}" "${#names[@]}" >&2
    printf 'e2e: failures below may be missing setup, not regressions. Run ./e2e.sh up && ./e2e.sh run for the whole order.\n' >&2
  fi
  local failed=0
  # Beside every suite, because each one sources it. Copied here rather than
  # baked into the image for the same reason the suites are: editing it takes
  # effect on the next run, with no rebuild.
  docker cp "$HERE/lib.sh" "$NAME":/root/ >/dev/null
  for n in "${names[@]}"; do
    local script="check-$n.sh"
    [ -f "$HERE/$script" ] || die "no $script here"
    docker cp "$HERE/$script" "$NAME":/root/ >/dev/null
    printf '\n######## %s\n' "$script"
    docker exec -e FARAMIR_E2E_SUDO="$SUDO" "$NAME" bash "/root/$script" || failed=1
  done
  printf '\n'
  [ $failed -eq 0 ] && echo "e2e: every suite passed" || echo "e2e: at least one suite failed"
  return $failed
}

cmd_sh() {
  running || die "the container is not up; run ./e2e.sh up"
  if [ $# -eq 0 ]; then docker exec -it "$NAME" bash; else docker exec "$NAME" "$@"; fi
}

# cmd_down removes every stack, not the one this invocation is addressed to:
# `both` leaves two up, and a `down` that took away half of them would leave
# containers running under names the next `down` has no reason to name either.
cmd_down() {
  local suffix
  for suffix in "" -rs; do
    docker rm -f "faramir-e2e$suffix" "managed-host$suffix" >/dev/null 2>&1 || true
    docker rmi -f "faramir-e2e$suffix" "faramir-managed$suffix" >/dev/null 2>&1 || true
    docker network rm "faramirnet$suffix" >/dev/null 2>&1 || true
  done
  # And whatever this invocation was pointed at, which the loop above misses when
  # a name was given rather than derived.
  docker rm -f "$NAME" "$MANAGED" >/dev/null 2>&1 || true
  docker rmi -f "$IMAGE" "$MANAGED_IMAGE" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  echo "e2e: containers, images and networks removed, both arrangements"
}

# usage is the header comment down to the end of the paragraph about SUDO: what
# the subcommands are, and how to pick an arrangement.
#
# Taken by counting the blank comment lines that separate the paragraphs rather
# than by a line number. The line number was 13 and the paragraph grew past it,
# so `./e2e.sh` with no arguments ended its own help mid-sentence, on "Every
# container, image and". A count follows the text it is counting.
usage() {
  awk 'NR == 1 { next }
       !/^#/ { exit }
       /^#$/ && ++blank > 2 { exit }
       { sub(/^# ?/, ""); print }' "$0"
}

case "${1:-}" in
  fetch) shift; cmd_fetch "$@";;
  up) shift; cmd_up "$@";;
  run) shift; cmd_run "$@";;
  sh) shift; cmd_sh "$@";;
  cp) shift; cmd_cp "$@";;
  down) shift; cmd_down "$@";;
  both) shift; cmd_both "$@";;
  *) usage; exit 2;;
esac

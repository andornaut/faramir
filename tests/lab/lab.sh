#!/bin/bash
# Driver for the guard lab.  Run from this directory.
#
#   ./lab.sh up            build the binary and image, start the container, bootstrap
#   ./lab.sh run NAME...   copy in and run check-NAME.sh (default: every suite)
#   ./lab.sh sh [cmd...]   a shell in the container, or one command
#   ./lab.sh cp FILE...    copy a script in without running it
#   ./lab.sh down          remove the container and image
#
# `up` is safe to re-run: it rebuilds the binary from the current tree and
# re-bootstraps, which is idempotent.
#
# sops, age and age-keygen must be present beside this script: the image has no
# network, so they are copied in rather than downloaded.  See README.md.
set -eu

NAME=guardlab
IMAGE=faramir-guardlab
# A second host the broker's key is the only way into, on a network of their
# own, so the ssh suite can put the relay to a real sshd rather than to a stub.
MANAGED=managed-host
MANAGED_IMAGE=faramir-managed
NETWORK=faramirnet
HERE=$(cd "$(dirname "$0")" && pwd)
# The tree under test, two levels up from tests/lab.
REPO=${REPO:-$(cd "$HERE/../.." && pwd)}
SUITES=(init project config disclose plugin gemini guard wrap leak stream mcp exec logs ssh doctor approval secrets uninstall)

die() { printf 'lab: %s\n' "$1" >&2; exit 1; }
running() { [ "$(docker inspect -f '{{.State.Running}}' $NAME 2>/dev/null)" = true ]; }

# build_skew produces a second binary reporting a version the first one does
# not, which is what the doctor suite swaps in to make the broker and the CLI
# disagree.  The version is a constant rather than a linker variable, so another
# compile is the only way to a different one; -overlay swaps the one file at
# compile time so that the tree is never edited to build it.
build_skew() {
  local work
  work=$(mktemp -d)
  sed -E 's/(const Version = )".*"/\1"9.9.9"/' "$REPO/internal/version/version.go" > "$work/version.go"
  grep -q '9\.9\.9' "$work/version.go" || die "the version constant is not where build_skew looks for it"
  printf '{"Replace":{"%s":"%s"}}\n' \
    "$REPO/internal/version/version.go" "$work/version.go" > "$work/overlay.json"
  ( cd "$REPO" && go build -overlay "$work/overlay.json" -o "$HERE/faramir-skew" ./cmd/faramir )
  rm -rf "$work"
}

cmd_up() {
  echo "== building the binary from $REPO"
  ( cd "$REPO" && go build -o "$HERE/faramir" ./cmd/faramir )
  build_skew
  for tool in sops age age-keygen; do
    [ -f "$HERE/$tool" ] || die "$tool is missing from the build context; copy it in beside faramir"
  done
  echo "== building the image"
  docker build -q -f "$HERE/Dockerfile.guardlab" -t $IMAGE "$HERE" >/dev/null
  echo "== building the managed host image"
  docker build -q -f "$HERE/Dockerfile.managed" -t $MANAGED_IMAGE "$HERE" >/dev/null
  docker network inspect $NETWORK >/dev/null 2>&1 || docker network create $NETWORK >/dev/null
  echo "== starting the containers"
  docker rm -f $NAME $MANAGED >/dev/null 2>&1 || true
  # --network-alias, so the broker dials the name the suite and the known_hosts
  # entry both use.
  docker run -d --name $MANAGED --network $NETWORK --network-alias $MANAGED \
    $MANAGED_IMAGE >/dev/null
  # Privileged with the host's cgroup namespace: systemd inside a container
  # needs a writable cgroup tree, and a private namespace leaves it exiting 255.
  docker run -d --name $NAME --privileged --cgroupns=host --network $NETWORK \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw $IMAGE >/dev/null
  for _ in $(seq 30); do
    [ "$(docker exec $NAME systemctl is-system-running 2>/dev/null)" = running ] && break
    sleep 1
  done
  running || die "the container did not come up"
  echo "== bootstrapping"
  docker cp "$HERE/plugin-harness.mjs" $NAME:/root/
  docker cp "$HERE/bootstrap-guard.sh" $NAME:/root/
  docker exec $NAME bash /root/bootstrap-guard.sh
  wire_managed_host
}

# wire_managed_host is the part no container can do for itself: the broker's
# public key into the managed host's authorized_keys, and the managed host's
# host key into the file the executor verifies against.  Both directions, or a
# brokered ssh fails and the suite cannot tell "the relay is broken" from "these
# two hosts were never introduced".
wire_managed_host() {
  echo "== introducing the broker and $MANAGED"
  for _ in $(seq 30); do
    docker exec $MANAGED test -f /etc/ssh/ssh_host_ed25519_key.pub && break
    sleep 1
  done
  local pub
  pub=$(docker exec $NAME cat /etc/faramir/id_ed25519.pub)
  docker exec $MANAGED bash -c "printf '%s\n' '$pub' > /home/deploy/.ssh/authorized_keys
    chown deploy:deploy /home/deploy/.ssh/authorized_keys
    chmod 0600 /home/deploy/.ssh/authorized_keys"
  # The system-wide file, which every account reads: the executor has no way to
  # be prompted to accept a key, so an unpinned host is refused before the
  # broker's key is offered.
  local hostkey
  hostkey=$(docker exec $MANAGED cat /etc/ssh/ssh_host_ed25519_key.pub)
  docker exec $NAME bash -c "printf '%s %s\n' '$MANAGED' '$(printf '%s' "$hostkey" | cut -d" " -f1,2)' \
    >> /etc/ssh/ssh_known_hosts; chmod 0644 /etc/ssh/ssh_known_hosts"
  docker exec $NAME sh -c "command -v ssh >/dev/null" \
    || echo "lab: the broker image has no ssh client; the ssh suite will not run"
}

cmd_cp() { for f in "$@"; do docker cp "$HERE/$f" $NAME:/root/; done; }

cmd_run() {
  running || die "the container is not up; run ./lab.sh up"
  local names=("$@")
  [ ${#names[@]} -eq 0 ] && names=("${SUITES[@]}")
  local failed=0
  # Beside every suite, because each one sources it.  Copied here rather than
  # baked into the image for the same reason the suites are: editing it takes
  # effect on the next run, with no rebuild.
  docker cp "$HERE/lib.sh" $NAME:/root/ >/dev/null
  for n in "${names[@]}"; do
    local script="check-$n.sh"
    [ -f "$HERE/$script" ] || die "no $script here"
    docker cp "$HERE/$script" $NAME:/root/ >/dev/null
    printf '\n######## %s\n' "$script"
    docker exec $NAME bash "/root/$script" || failed=1
  done
  printf '\n'
  [ $failed -eq 0 ] && echo "lab: every suite passed" || echo "lab: at least one suite failed"
  return $failed
}

cmd_sh() {
  running || die "the container is not up; run ./lab.sh up"
  if [ $# -eq 0 ]; then docker exec -it $NAME bash; else docker exec $NAME "$@"; fi
}

cmd_down() {
  docker rm -f $NAME $MANAGED >/dev/null 2>&1 || true
  docker rmi -f $IMAGE $MANAGED_IMAGE >/dev/null 2>&1 || true
  docker network rm $NETWORK >/dev/null 2>&1 || true
  echo "lab: containers, images and network removed"
}

case "${1:-}" in
  up) shift; cmd_up "$@";;
  run) shift; cmd_run "$@";;
  sh) shift; cmd_sh "$@";;
  cp) shift; cmd_cp "$@";;
  down) shift; cmd_down "$@";;
  *) sed -n '2,12p' "$0" | sed 's/^# \?//'; exit 2;;
esac

#!/usr/bin/env bash
# Runs in the container run.sh starts, as root, and runs the arguments as the
# unprivileged tester account (uid 19001) in a copy of the checkout. Root does
# the setup alone, and nothing from the host is mounted writable.
set -euo pipefail

# Only cache roots need ownership setup: their contents are written by tester.
chown tester:tester /work /go/pkg/mod /cache
checkout_gid=${FARAMIR_CHECKOUT_GID:?}
[[ "$checkout_gid" =~ ^[0-9]+$ ]] || { echo 'tests/go: invalid checkout group' >&2; exit 1; }
checkout_group=$(getent group "$checkout_gid" | cut -d: -f1 || true)
if [ -z "$checkout_group" ]; then
  groupadd -g "$checkout_gid" checkout
  checkout_group=checkout
fi
usermod -a -G "$checkout_group" tester

# Every brokered command is confined to a cgroup of its own, and the executor
# refuses to run where it cannot make one, so this shell moves into a cgroup the
# tester owns before handing over: the tests inherit it, as they do in CI.
# Without it a couple of dozen tests skip and the run still passes. The cgroup
# root is owned by root, which is why the setup runs as root.
cg=/sys/fs/cgroup/faramir-test
mkdir -p "$cg"
chown -R tester:tester "$cg"
echo $$ >"$cg/cgroup.procs"

# /out is in the container's own filesystem, and run.sh copies it to the host
# with `docker cp` once the container has stopped.
if [ -n "${FARAMIR_OUT:-}" ]; then
  mkdir -p /out
  chown tester:tester /out
fi

cd /work
exec setpriv --reuid=tester --regid=tester --init-groups \
  env HOME=/tmp GOCACHE=/cache/go-build GOMODCACHE=/go/pkg/mod \
  bash -ec 'tar --no-same-owner -xf - -C /work; exec "$@"' _ "$@"

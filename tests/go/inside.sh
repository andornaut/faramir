#!/usr/bin/env bash
# Runs in the container run.sh starts, as root, and runs the arguments as the
# unprivileged tester account in a copy of the checkout.
set -euo pipefail

# A copy, so nothing a test writes reaches the checkout, which is mounted
# read-only. Build output and dependencies are left behind.
tar -C /src --exclude=./bin --exclude=./node_modules --exclude=./.git -cf - . |
  tar -C /work -xf -
chown -R tester:tester /work /go/pkg/mod /cache

# Every brokered command is confined to a cgroup of its own, and the executor
# refuses to run where it cannot make one, so this shell moves into a cgroup the
# tester owns before handing over: the tests inherit it, as they do in CI.
# Without it a couple of dozen tests skip and the run still passes.
cg=/sys/fs/cgroup/faramir-test
mkdir -p "$cg"
chown -R tester:tester "$cg"
echo $$ >"$cg/cgroup.procs"

cd /work
as_tester=(setpriv --reuid=tester --regid=tester --init-groups
  env HOME=/home/tester GOCACHE=/cache/go-build GOMODCACHE=/go/pkg/mod)
[ -d /host-out ] || exec "${as_tester[@]}" "$@"

# /out is written by tester, whose uid need not be the caller's, so it is a
# directory here and its contents go to the caller's directory afterwards, owned
# by the caller. Whatever the command's status: a failing fuzz run is the one
# that wrote a crasher.
mkdir -p /out
chown tester:tester /out
status=0
"${as_tester[@]}" "$@" || status=$?
chown -R "$FARAMIR_OUT_OWNER" /out
cp -a /out/. /host-out/
exit "$status"

#!/usr/bin/env bash
# Runs a command, by default the Go suite, in a container that can write to
# nothing on the host: tracked working-tree files are streamed into a
# tmpfs, the module and build caches are Docker volumes, and the tests run as
# uid 19001, which owns nothing on the host.
#
#   tests/go/run.sh                      go test -v ./...
#   tests/go/run.sh go test ./internal/guard
#
# FARAMIR_TEST_OUT names a host directory that what a run writes to /out is
# copied into, by `docker cp` as the caller once the container stops: the one
# place a run can leave a file, a coverage profile or a fuzz crasher. The copy
# happens whatever the command's status, since a failing fuzz run is the one
# that wrote a crasher.
#
# SYS_ADMIN permits remounting only the private cgroup namespace. The suite
# runs as an unprivileged account, without host devices or a host cgroup bind.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
name=faramir-go-test-$$
image=$name
modules=$name-modules
cache=$name-cache
trap '
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$modules" "$cache" >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
' EXIT
sops=$root/tests/e2e/sops

[ -x "$sops" ] || {
  echo "tests/go: $sops is missing; tests/e2e/e2e.sh fetch downloads it" >&2
  exit 1
}
[ $# -gt 0 ] || set -- go test -v ./...

tar -C "$root" -cf - tests/go/Dockerfile tests/go/inside.sh tests/cgroup.sh |
  docker build -q -t "$image" -f tests/go/Dockerfile - >/dev/null
args=(-i --cgroupns=private --cap-add SYS_ADMIN
  --security-opt apparmor=unconfined --security-opt seccomp=unconfined
  --cpus 2 --memory 4g --pids-limit 512
  -e CGO_ENABLED="${CGO_ENABLED:-0}"
  -e GOMAXPROCS=2 -e GOFLAGS=-p=2
  --mount "type=bind,source=$sops,target=/usr/local/bin/sops,readonly"
  -v "$modules:/go/pkg/mod" -v "$cache:/cache"
  --tmpfs "/work:exec,size=4g" --tmpfs "/tmp:exec,size=4g")

# Each run owns its container, image tag and disposable scratch volumes.
if [ -z "${FARAMIR_TEST_OUT:-}" ]; then
  "$root/tests/source.sh" | docker run --rm --name "$name" "${args[@]}" "$image" "$@"
  exit
fi

# A container kept after it stops, so /out can be copied from it, and named
# after this process so concurrent runs do not collide.
mkdir -p "$FARAMIR_TEST_OUT"
status=0
"$root/tests/source.sh" |
  docker run --name "$name" -e FARAMIR_OUT=1 "${args[@]}" "$image" "$@" || status=$?
docker cp -q "$name":/out/. "$FARAMIR_TEST_OUT" || { [ "$status" -ne 0 ] || status=1; }
exit "$status"

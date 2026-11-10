#!/usr/bin/env bash
# Runs a command, by default the Go suite, in a container that can write to
# nothing on the host: tracked working-tree files are streamed into a
# tmpfs, reusable module and build caches are Docker volumes, and tests run as
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
# shellcheck source=cache.sh
source "$here/cache.sh"
go_cache_mounts
scratch=$(mktemp -d)
owned=0
trap '
  if [ "$owned" = 1 ]; then docker rm -f "$name" >/dev/null 2>&1 || true; fi
  find "$scratch" -depth -delete
' EXIT
sops=$root/tests/e2e/sops

[ -x "$sops" ] || {
  echo "tests/go: $sops is missing; tests/e2e/e2e.sh fetch downloads it" >&2
  exit 1
}
[ $# -gt 0 ] || set -- go test -v -count=1 -p=1 -parallel=4 ./...
[ -z "$(docker ps -a --filter "name=^/$name$" --format '{{.Names}}')" ] || {
  echo 'tests/go: container name already exists' >&2; exit 1
}
revision=$(git -C "$root" rev-parse HEAD)
source_state=$(git -C "$root" status --porcelain --untracked-files=all)
"$root/tests/source.sh" > "$scratch/source.tar"
digest=$(sha256sum "$scratch/source.tar" | cut -d ' ' -f1)

node_version=$(cat "$root/.nvmrc")
tar -C "$root" -cf - tests/go/Dockerfile tests/go/inside.sh tests/cgroup.sh |
  docker build -q -t faramir-go-test:local --iidfile "$scratch/image.id" \
    --build-arg "NODE_VERSION=${node_version#v}" -f tests/go/Dockerfile - >/dev/null
image=$(cat "$scratch/image.id")
args=(-i --cgroupns=private --cap-add SYS_ADMIN
  --security-opt apparmor=unconfined --security-opt seccomp=unconfined
  --cpus 2 --memory 4g --pids-limit 512
  -e CGO_ENABLED="${CGO_ENABLED:-0}"
  -e GOMAXPROCS=2 -e GOFLAGS=-p=2
  -e "FARAMIR_CHECKOUT_GID=$(stat -c %g "$root")"
  --mount "type=bind,source=$sops,target=/usr/local/bin/sops,readonly"
  "${GO_CACHE_MOUNTS[@]}"
  --tmpfs "/work:exec,size=4g,uid=19001,gid=19001,mode=0700" --tmpfs "/tmp:exec,size=4g")

if [ -n "${FARAMIR_TEST_OUT:-}" ]; then
  case "$FARAMIR_TEST_OUT" in
    /*) ;;
    *) FARAMIR_TEST_OUT=$root/$FARAMIR_TEST_OUT;;
  esac
  destination=$(realpath -m "$FARAMIR_TEST_OUT")
  [ "$destination" = "$FARAMIR_TEST_OUT" ] || {
    echo 'tests/go: export destination contains a symlink or noncanonical component' >&2; exit 1
  }
  [ ! -L "$destination" ] || { echo 'tests/go: export destination is a symlink' >&2; exit 1; }
  if [ -e "$destination" ] && [ -n "$(find "$destination" -type l -print -quit)" ]; then
    echo 'tests/go: export destination contains a symlink' >&2; exit 1
  fi
  mkdir -p "$FARAMIR_TEST_OUT"
  args+=(-e FARAMIR_OUT=1)
fi
docker create --name "$name" "${args[@]}" "$image" "$@" >/dev/null
owned=1
status=0
docker start -ai "$name" < "$scratch/source.tar" || status=$?
if [ -n "${FARAMIR_TEST_OUT:-}" ]; then
  docker cp -q "$name":/out/. "$FARAMIR_TEST_OUT" || { [ "$status" -ne 0 ] || status=1; }
fi
after=$("$root/tests/source.sh" | sha256sum | cut -d ' ' -f1)
if [ "$(git -C "$root" rev-parse HEAD)" != "$revision" ] ||
  [ "$(git -C "$root" status --porcelain --untracked-files=all)" != "$source_state" ] || [ "$after" != "$digest" ]; then
  echo 'tests/go: source changed during verification; discarding result' >&2
  exit 125
fi
exit "$status"

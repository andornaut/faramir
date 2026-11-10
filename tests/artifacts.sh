#!/usr/bin/env bash
# Build public artifacts in isolation, or verify an exact-source E2E bundle.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd -P)
mode=${1:?want fetch, e2e, build or verify-e2e}
case "$mode" in fetch|e2e|build|verify-e2e) ;; *) echo 'want fetch, e2e, build or verify-e2e' >&2; exit 2;; esac
version=${FARAMIR_BUILD_VERSION:-dev}
[[ "$version" = dev || "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo 'artifacts: build version must be dev or a release version without v' >&2; exit 1
}
revision=$(git -C "$root" rev-parse HEAD)
source_state=$(git -C "$root" status --porcelain --untracked-files=all)
dirty=false
if [ -n "$source_state" ]; then dirty=true; fi
if [ -n "${GITHUB_SHA:-}" ] && { [ "$revision" != "$GITHUB_SHA" ] || [ "$dirty" != false ]; }; then
  echo 'artifacts: CI needs a clean checkout of its exact commit' >&2; exit 1
fi
if [ "$version" != dev ] && [ "$dirty" != false ]; then
  echo 'artifacts: a release version requires a clean source tree' >&2; exit 1
fi
build=${revision:0:12}
if [ "$dirty" = true ]; then build+=-modified; fi
if [ "$version" != dev ]; then build=; fi

source_digest() { "$root/tests/source.sh" | sha256sum | cut -d ' ' -f1; }
output_directory() {
  local directory=$1 parent
  parent=$(dirname "$directory")
  [ "$(realpath -e "$parent")" = "$parent" ] || {
    echo 'artifacts: output parent contains a symlink' >&2; return 1
  }
  if [ -e "$directory" ] || [ -L "$directory" ]; then
    [ -d "$directory" ] && [ ! -L "$directory" ] && [ "$(realpath -e "$directory")" = "$directory" ] || {
      echo 'artifacts: output directory contains a symlink' >&2; return 1
    }
  fi
}
output_directory "$root/tests/e2e"
if [ "$mode" = build ]; then output_directory "$root/bin"; fi
verify_e2e() {
  local key value field expected
  local -A manifest=()
  local file=$root/tests/e2e/binaries.manifest
  [ -f "$file" ] && [ ! -L "$file" ] || { echo 'artifacts: missing E2E manifest' >&2; return 1; }
  while IFS='=' read -r key value || [ -n "$key$value" ]; do
    case "$key" in format|revision|source_sha256|version|build|dirty|skew_version|normal_sha256|skew_sha256) ;;
      *) echo 'artifacts: unknown E2E manifest field' >&2; return 1;;
    esac
    [ -z "${manifest[$key]+present}" ] || { echo 'artifacts: duplicate E2E manifest field' >&2; return 1; }
    manifest[$key]=$value
  done < "$file"
  for field in format revision source_sha256 version build dirty skew_version normal_sha256 skew_sha256; do
    [ -n "${manifest[$field]+present}" ] || { echo 'artifacts: incomplete E2E manifest' >&2; return 1; }
  done
  for field in source_sha256 normal_sha256 skew_sha256; do
    [[ "${manifest[$field]}" =~ ^[0-9a-f]{64}$ ]] || {
      echo 'artifacts: invalid E2E manifest digest' >&2; return 1
    }
  done
  [ "${manifest[format]}" = 1 ] && [ "${manifest[revision]}" = "$revision" ] &&
    [ "${manifest[version]}" = "$version" ] && [ "${manifest[build]}" = "$build" ] &&
    [ "${manifest[dirty]}" = "$dirty" ] && [ "${manifest[skew_version]}" = 9.9.9-skew ] || {
      echo 'artifacts: E2E bundle revision, version or source state does not match' >&2; return 1
    }
  expected=$(source_digest) || return 1
  [ "${manifest[source_sha256]}" = "$expected" ] || {
    echo 'artifacts: E2E bundle source digest does not match' >&2; return 1
  }
  for field in normal skew; do
    file=$root/tests/e2e/faramir
    if [ "$field" = skew ]; then file+=-skew; fi
    [ -f "$file" ] && [ ! -L "$file" ] && [ -x "$file" ] || {
        echo 'artifacts: E2E binary digest or file mode does not match' >&2; return 1
      }
    value=$(sha256sum "$file") || return 1
    [ "${manifest[${field}_sha256]}" = "${value%% *}" ] || {
      echo 'artifacts: E2E binary digest or file mode does not match' >&2; return 1
    }
  done
}
if [ "$mode" = verify-e2e ]; then verify_e2e; exit; fi

# shellcheck source=go/cache.sh
source "$root/tests/go/cache.sh"
go_cache_mounts
scratch=$(mktemp -d)
name=faramir-artifacts-$$
owned=0
cleanup() {
  if [ "$owned" = 1 ]; then docker rm -f "$name" >/dev/null 2>&1 || true; fi
  find "$scratch" -depth -delete
}
trap cleanup EXIT
[ -z "$(docker ps -a --filter "name=^/$name$" --format '{{.Names}}')" ] || {
  echo 'artifacts: container name already exists' >&2; exit 1
}
"$root/tests/source.sh" > "$scratch/source.tar"
digest=$(sha256sum "$scratch/source.tar" | cut -d ' ' -f1)
docker create --name "$name" --cpus 2 --memory 3g --pids-limit 256 \
  --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges \
  --mount "type=bind,source=$scratch/source.tar,target=/source.tar,readonly" \
  "${GO_CACHE_MOUNTS[@]}" --tmpfs /work:exec,uid=19001,gid=19001,mode=0700 \
  --env FARAMIR_ARTIFACT_CONTAINER=1 --env CGO_ENABLED=0 --env HOME=/tmp \
  --env "GOOS=${GOOS:-}" --env "GOARCH=${GOARCH:-}" \
  --env "FARAMIR_BUILD_LDFLAGS=${2:--s -w}" --env "FARAMIR_BUILD_VERSION=$version" \
  --env "FARAMIR_BUILD_REVISION=$revision" --env "FARAMIR_BUILD_SOURCE_SHA256=$digest" \
  --env "FARAMIR_BUILD_DIRTY=$dirty" --env "FARAMIR_CHECKOUT_GID=$(stat -c %g "$root")" \
  --env GOTOOLCHAIN=local --env GOCACHE=/cache/go-build --env GOMODCACHE=/go/pkg/mod \
  --env GOMAXPROCS=2 --env GOFLAGS=-p=2 --workdir /work golang:1.27 bash -ec '
    mkdir -p /out
    chown 19001:19001 /go/pkg/mod /cache /out
    exec setpriv --reuid=19001 --regid=19001 --groups="$FARAMIR_CHECKOUT_GID" \
      bash -ec '\''test "$(id -u)" = 19001
        grep -qE "^CapEff:[[:space:]]+0+$" /proc/self/status
        tar --no-same-owner -xf /source.tar -C /work
        exec bash tests/artifacts-inside.sh "$@"'\'' _ "$@"
  ' _ "$mode" >/dev/null
owned=1
docker start -ai "$name"
[ "$(git -C "$root" rev-parse HEAD)" = "$revision" ] &&
  [ "$(git -C "$root" status --porcelain --untracked-files=all)" = "$source_state" ] &&
  [ "$(source_digest)" = "$digest" ] || {
    echo 'artifacts: source changed during the build; discarding outputs' >&2; exit 1
  }
case "$mode" in
  fetch) paths=(tests/e2e/sops tests/e2e/age tests/e2e/age-keygen);;
  e2e) paths=(tests/e2e/faramir tests/e2e/faramir-skew tests/e2e/binaries.manifest);;
  build) mkdir -p "$root/bin"; paths=(bin/faramir);;
esac
for path in "${paths[@]}"; do
  [ ! -L "$root/$path" ] || { echo 'artifacts: output file is a symlink' >&2; exit 1; }
  docker cp "$name:/out/$path" "$root/$path"
done
if [ "$mode" = e2e ]; then verify_e2e; fi

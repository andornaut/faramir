#!/usr/bin/env bash
# Build and download public test artifacts without executing project code on the host.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
mode=${1:?want fetch, e2e or build}
case "$mode" in fetch|e2e|build) ;; *) echo 'want fetch, e2e or build' >&2; exit 2;; esac
name=faramir-artifacts-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker create -i --name "$name" --cpus 2 --memory 3g --pids-limit 256 \
  --cap-drop ALL --security-opt no-new-privileges \
  --env FARAMIR_ARTIFACT_CONTAINER=1 --env CGO_ENABLED=0 \
  --env "GOOS=${GOOS:-}" --env "GOARCH=${GOARCH:-}" \
  --env "FARAMIR_BUILD_LDFLAGS=${2:--s -w}" \
  --env GOTOOLCHAIN=local --env GOCACHE=/work/cache \
  --env GOMAXPROCS=2 --env GOFLAGS=-p=2 \
  --workdir /work golang:1.27 bash -ec '
    tar --no-same-owner -xf -
    case "$1" in
      fetch) tests/e2e/e2e.sh fetch;;
      e2e) tests/e2e/e2e.sh build;;
      build) mkdir -p bin; go build -ldflags="$FARAMIR_BUILD_LDFLAGS" -trimpath -o bin/faramir ./cmd/faramir;;
    esac
  ' _ "$mode" >/dev/null
"$root/tests/source.sh" | docker start -ai "$name"
case "$mode" in
  fetch) paths=(tests/e2e/sops tests/e2e/age tests/e2e/age-keygen);;
  e2e) paths=(tests/e2e/faramir tests/e2e/faramir-skew);;
  build) mkdir -p "$root/bin"; paths=(bin/faramir);;
esac
for path in "${paths[@]}"; do
  docker cp "$name:/work/$path" "$root/$path"
done

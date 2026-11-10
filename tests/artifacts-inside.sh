#!/usr/bin/env bash
# Compile and verify public artifacts inside the unprivileged build container.
set -euo pipefail
mode=${1:?want fetch, e2e or build}
export_artifacts() {
  local path
  for path in "$@"; do
    mkdir -p "/out/$(dirname "$path")"
    cp "$path" "/out/$path"
  done
}
if [ "$mode" = fetch ]; then
  tests/e2e/e2e.sh fetch
  export_artifacts tests/e2e/sops tests/e2e/age tests/e2e/age-keygen
  exit
fi

version=${FARAMIR_BUILD_VERSION:?}
build=${FARAMIR_BUILD_REVISION:0:12}
if [ "$FARAMIR_BUILD_DIRTY" = true ]; then build+=-modified; fi
if [ "$version" != dev ]; then build=; fi
stamp="-X github.com/andornaut/faramir/internal/version.Version=$version -X github.com/andornaut/faramir/internal/version.Build=$build"
flags="${FARAMIR_BUILD_LDFLAGS:-} $stamp"

if [ "$mode" = build ]; then
  mkdir -p bin
  go build -trimpath -ldflags "$flags" -o bin/faramir ./cmd/faramir
  info=$(go version -m bin/faramir)
  grep -qF "internal/version.Version=$version" <<< "$info"
  export_artifacts bin/faramir
  exit
fi

# E2E programs run on the container host rather than a cross-build target.
export GOOS=linux
GOARCH=$(go env GOHOSTARCH)
export GOARCH
go build -trimpath -ldflags "$flags" -o tests/e2e/faramir ./cmd/faramir
skew=9.9.9-skew
go build -trimpath -ldflags "${FARAMIR_BUILD_LDFLAGS:-} -X github.com/andornaut/faramir/internal/version.Version=$skew" \
  -o tests/e2e/faramir-skew ./cmd/faramir
[ "$(tests/e2e/faramir --version)" = "faramir $version" ]
[ "$(tests/e2e/faramir-skew --version)" = "faramir $skew" ]
info=$(go version -m tests/e2e/faramir)
grep -qF "internal/version.Build=$build" <<< "$info"

{
  printf 'format=1\nrevision=%s\nsource_sha256=%s\nversion=%s\nbuild=%s\ndirty=%s\nskew_version=%s\n' \
    "$FARAMIR_BUILD_REVISION" "$FARAMIR_BUILD_SOURCE_SHA256" "$version" "$build" "$FARAMIR_BUILD_DIRTY" "$skew"
  printf 'normal_sha256=%s\n' "$(sha256sum tests/e2e/faramir | cut -d ' ' -f1)"
  printf 'skew_sha256=%s\n' "$(sha256sum tests/e2e/faramir-skew | cut -d ' ' -f1)"
} > tests/e2e/binaries.manifest
export_artifacts tests/e2e/faramir tests/e2e/faramir-skew tests/e2e/binaries.manifest

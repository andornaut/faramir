# shellcheck shell=bash
# Docker-owned caches hold dependencies and compiler outputs, never test state.
# Go keys compiler entries by toolchain, inputs and build flags.
cache_volume() {
  local kind=$1 name=$2 expected
  expected="io.faramir.cache=$kind-v1"
  if [ -z "$(docker volume ls --filter "name=^$name$" --format '{{.Name}}')" ]; then
    docker volume create --label "$expected" "$name" >/dev/null
  fi
  [ "$(docker volume ls --filter "name=^$name$" --filter "label=$expected" --format '{{.Name}}')" = "$name" ] || {
    echo 'tests: cache volume exists without the expected ownership label; refusing to adopt it' >&2
    return 1
  }
}
go_cache_mounts() {
  local name
  for name in "${FARAMIR_GO_MODULE_CACHE:-faramir-go-modules}" "${FARAMIR_GO_BUILD_CACHE:-faramir-go-build}"; do
    [[ "$name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || {
      printf 'tests: invalid Docker cache volume name: %s\n' "$name" >&2
      return 1
    }
  done
  cache_volume modules "${FARAMIR_GO_MODULE_CACHE:-faramir-go-modules}"
  cache_volume build "${FARAMIR_GO_BUILD_CACHE:-faramir-go-build}"
  # shellcheck disable=SC2034 # The host runners consume this shared argument array.
  GO_CACHE_MOUNTS=(
    --mount "type=volume,source=${FARAMIR_GO_MODULE_CACHE:-faramir-go-modules},target=/go/pkg/mod"
    --mount "type=volume,source=${FARAMIR_GO_BUILD_CACHE:-faramir-go-build},target=/cache"
  )
}

# shellcheck shell=bash
# Docker-owned caches hold dependencies and compiler outputs, never test state.
# Go keys compiler entries by toolchain, inputs and build flags.
go_cache_mounts() {
  local name
  for name in "${FARAMIR_GO_MODULE_CACHE:-faramir-go-modules}" "${FARAMIR_GO_BUILD_CACHE:-faramir-go-build}"; do
    [[ "$name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || {
      printf 'tests: invalid Docker cache volume name: %s\n' "$name" >&2
      return 1
    }
  done
  GO_CACHE_MOUNTS=(
    --mount "type=volume,source=${FARAMIR_GO_MODULE_CACHE:-faramir-go-modules},target=/go/pkg/mod"
    --mount "type=volume,source=${FARAMIR_GO_BUILD_CACHE:-faramir-go-build},target=/cache"
  )
}

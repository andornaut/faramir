#!/usr/bin/env bash
# Archive tracked working-tree files without local credentials or build output.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
git -C "$root" ls-files -z --cached -- . \
  ':!**/.env*' ':!**/.npmrc' ':!**/.netrc' \
  ':!**/.ssh/**' ':!**/.private/**' \
  ':!**/*.pem' ':!**/*.key' ':!**/*.p12' ':!**/*.pfx' |
  tar -C "$root" --no-recursion --null --files-from=- -cf -

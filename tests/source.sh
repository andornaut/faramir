#!/usr/bin/env bash
# Archive tracked source with stable metadata, excluding local credentials.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd -P)

excluded() {
  case "${1,,}" in
    /*|..|../*|*/../*|*/..|.git|.git/*|*/.git|*/.git/*) return 0;;
    agents.md|*/agents.md|claude.md|*/claude.md|gemini.md|*/gemini.md) return 0;;
    .env*|*/.env*|*.env|.dev.vars*|*/.dev.vars*) return 0;;
    .npmrc|*/.npmrc|.netrc|*/.netrc|.pypirc|*/.pypirc|.git-credentials|*/.git-credentials) return 0;;
    .ssh/*|*/.ssh/*|.private/*|*/.private/*|.aws/*|*/.aws/*) return 0;;
    credentials|credentials.*|*/credentials|*/credentials.*|*.pem|*.key|*.crt|*.cer|*.p12|*.pfx|*.age|*.gpg|*.sops.*) return 0;;
  esac
  return 1
}

files() {
  local path parent relative
  while IFS= read -r -d '' path; do
    excluded "$path" && continue
    parent=$(realpath -e -- "$root/$(dirname -- "$path")")
    case "$parent" in
      "$root") relative=$(basename -- "$path");;
      "$root"/*) relative=${parent#"$root/"}/$(basename -- "$path");;
      *) printf 'source: path escapes checkout: %s\n' "$path" >&2; return 1;;
    esac
    if excluded "$relative"; then
      printf 'source: path resolves to an excluded location: %s\n' "$path" >&2
      return 1
    fi
    if [ ! -f "$root/$path" ] && [ ! -L "$root/$path" ]; then
      printf 'source: not a regular file or symlink: %s\n' "$path" >&2
      return 1
    fi
    printf '%s\0' "$path"
  done
}

git -C "$root" ls-files -z --cached -- . | files |
  tar -C "$root" --no-recursion --null --verbatim-files-from --files-from=- \
    --format=gnu --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' -cf -

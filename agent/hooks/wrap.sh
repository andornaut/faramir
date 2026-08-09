# shellcheck shell=bash
# Run one command with its output redacted.  Sourced, never executed:
#
#   source /usr/local/libexec/faramir/wrap.sh '<command>'
#
# The guard rewrites every Bash tool call into that line.  Three things decide
# the shape; see docs/design.md.
#
# Sourced, because the agent's shell persists between tool calls: a child would
# lose every "cd", "export" and shell function the command sets.  One simple
# command, because the permission matcher refuses a rule against a compound
# statement.  Redacted after the command finishes, a pipeline putting it in a
# subshell and process substitution racing the shell.
#
# Every failure fails closed: output that could not be redacted is never
# shown.

# /dev/shm before mktemp's default: the file holds unredacted output, so it
# belongs in memory.  0600 either way, and removed once read.
__frf=$(mktemp "${XDG_RUNTIME_DIR:-/dev/shm}/faramir.XXXXXX" 2>/dev/null ||
  mktemp /dev/shm/faramir.XXXXXX 2>/dev/null || mktemp)

if [ -z "$__frf" ]; then
  # Nothing to capture into, so the command does not run: it would print
  # whatever it found straight through.
  echo "faramir: no file to capture output into, so the command was not run" >&2
  __frc=1
else
  # ":;" keeps a comment-only command from forming an empty group.
  { :; eval "$1"
  } >"$__frf" 2>&1
  __frc=$?

  # A second file rather than stdout, so a redaction that fails part way
  # through cannot have printed what it did not redact.
  if "${FARAMIR_CLI:-/usr/local/bin/faramir}" redact <"$__frf" >"${__frf}.out"; then
    cat "${__frf}.out"
  else
    # The command ran, so what it set in this shell is intact; only the output
    # is withheld.  A missing or too-old faramir lands here too.
    echo "faramir: the output was withheld because it could not be redacted" >&2
    # A withheld output must not read as a clean success.
    [ "$__frc" -eq 0 ] && __frc=1
  fi
  rm -f "$__frf" "${__frf}.out"
fi

# Restores the status the caller reads, and clears the variables: this runs in
# the caller's shell.  The status is expanded into the eval string before unset
# runs.
eval "unset __frf __frc; ( exit $__frc )"

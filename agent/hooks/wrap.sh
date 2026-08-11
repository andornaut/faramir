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
# command, so the guard's idempotence check is a prefix test and the rewritten
# text stays legible to whatever reads it next.  Redacted after the command
# finishes, a pipeline putting it in a subshell and process substitution racing
# the shell.
#
# Every failure fails closed: output that could not be redacted is never
# shown.

# The capture files hold unredacted output, so they go in a directory no other
# account can enter, and nowhere else.  XDG_RUNTIME_DIR is that directory: a
# tmpfs the login session owns at 0700.  There is deliberately no /dev/shm
# fallback, which is 1777: "private" there is something to be argued rather than
# asserted, and a directory another account can write is one where the name of a
# file that does not exist yet is a name it can create first.
#
# Required, not preferred.  Without it the command does not run at all, which is
# the same answer as a redactor that will not start: XDG_RUNTIME_DIR is unset
# under sudo and in cron, so an agent running there gets a refusal it can read
# rather than output nothing checked.
# The test is that no other account holds a bit on it, not that it is exactly
# 0700: what matters is that nobody else can enter it or create a name in it.
__frd=${XDG_RUNTIME_DIR:-}
__frm=$(stat -c %a "$__frd" 2>/dev/null || echo 777)
if [ -n "$__frd" ] && [ -d "$__frd" ] && [ -O "$__frd" ] &&
  [ $((8#$__frm & 8#77)) -eq 0 ]; then
  # Two files from mktemp rather than one plus a derived "<name>.out": a name
  # nothing has created is not a file this owns, whoever else can reach it.
  __frf=$(mktemp "$__frd/faramir.XXXXXX" 2>/dev/null)
  __fro=$(mktemp "$__frd/faramir.XXXXXX" 2>/dev/null)
fi

if [ -z "${__frf:-}" ] || [ -z "${__fro:-}" ]; then
  # Nothing private to capture into, so the command does not run: it would print
  # whatever it found straight through.
  rm -f "${__frf:-}" "${__fro:-}"
  echo "faramir: no private directory to capture output into (XDG_RUNTIME_DIR is" \
    "unset, not yours, or readable by another account), so the command was not" \
    "run" >&2
  __frc=1
else
  # "exit" in the command ends this shell at the eval below, before the rm at the
  # end of this branch, and the capture file holds output that has not been
  # redacted yet.  An EXIT trap is what bash still runs on that path.
  #
  # This is sourced, so the trap is the caller's shell's: the one it had is saved
  # and put back once the files are gone.  On the exit path ours runs and the
  # caller's does not, bash keeping one handler per signal rather than chaining.
  __frt=$(trap -p EXIT)
  trap 'rm -f "$__frf" "$__fro"' EXIT

  # ":;" keeps a comment-only command from forming an empty group.
  { :; eval "$1"
  } >"$__frf" 2>&1
  __frc=$?

  # A second file rather than stdout, so a redaction that fails part way
  # through cannot have printed what it did not redact.
  if "${FARAMIR_CLI:-/usr/local/bin/faramir}" redact <"$__frf" >"$__fro"; then
    cat "$__fro"
  else
    # The command ran, so what it set in this shell is intact; only the output
    # is withheld.  A missing or too-old faramir lands here too.
    echo "faramir: the output was withheld because it could not be redacted" >&2
    # A withheld output must not read as a clean success.
    [ "$__frc" -eq 0 ] && __frc=1
  fi
  rm -f "$__frf" "$__fro"
  trap - EXIT
  eval "${__frt:-}"
fi

# Restores the status the caller reads, and clears the variables: this runs in
# the caller's shell.  The status is expanded into the eval string before unset
# runs.
eval "unset __frd __frm __frt __frf __fro __frc; ( exit $__frc )"

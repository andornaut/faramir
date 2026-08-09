# shellcheck shell=bash
# Run one command with its output redacted.  Sourced, never executed:
#
#   source /usr/local/libexec/faramir/wrap.sh '<command>'
#
# The guard rewrites every Bash tool call into that one line.  Three things
# decide this shape, and each of them rules out something simpler.
#
# Sourced, because the agent's shell persists between tool calls.  A wrapper
# that runs the command in a child loses every "cd", "export" and shell function
# it sets, and the next command runs somewhere else.  Sourcing runs here, and
# "eval" re-parses the command in this shell, so nothing is lost.
#
# One simple command, because the permission matcher refuses to match a rule
# against a compound statement: an inline "{ ...; } >file" rewrite is opaque to
# it however the rule is written.  This form at least reads as one command.  It
# does not restore permission matching, and nothing does: the rule an operator
# wrote names the program, and after the rewrite the program is "source".  That
# is why the hook approves what its deny list did not refuse; see docs/design.md.
#
# Redacted after the command finishes rather than through a pipe while it runs,
# because a pipeline puts the command in a subshell (losing the state again) and
# process substitution races: the shell moves on while the redactor is still
# writing, and whatever it had not written yet is lost.
#
# Every failure fails closed: output that could not be redacted is never shown.
# With nowhere to capture output the command does not run at all, and output
# that was captured but not redacted is withheld.  Both say so on stderr and
# return non-zero, so the caller reads a refusal rather than a silent success.
# The command's own status is what comes back when redaction worked.

# /dev/shm before mktemp's own default: the file holds the command's output
# before redaction, so it belongs in memory rather than on a disk.  0600 either
# way, and removed as soon as it has been read.
__frf=$(mktemp "${XDG_RUNTIME_DIR:-/dev/shm}/faramir.XXXXXX" 2>/dev/null ||
  mktemp /dev/shm/faramir.XXXXXX 2>/dev/null || mktemp)

if [ -z "$__frf" ]; then
  # Nothing to capture into means nothing to redact, so the command does not
  # run.  Letting it run here would print whatever it found straight through.
  echo "faramir: no file to capture output into, so the command was not run" >&2
  __frc=1
else
  # ":;" keeps a comment-only command from forming an empty group.
  { :; eval "$1"
  } >"$__frf" 2>&1
  __frc=$?

  # Redacted into a second file rather than straight to stdout, so a redaction
  # that fails part way through cannot have already printed the part it did not
  # redact.  Neither file outlives this block, and both hold text that has not
  # been shown, so /dev/shm again.
  if "${FARAMIR_CLI:-/usr/local/bin/faramir}" redact <"$__frf" >"${__frf}.out"; then
    cat "${__frf}.out"
  else
    # The command ran, so everything it set in this shell is intact; only its
    # output is withheld.  A faramir too old to have "redact", one that is not
    # installed, and a broker that could not be reached all land here.
    echo "faramir: the output was withheld because it could not be redacted" >&2
    # A withheld output must not read as a clean success.
    [ "$__frc" -eq 0 ] && __frc=1
  fi
  rm -f "$__frf" "${__frf}.out"
fi

# Restores the status the caller reads, the command's own whenever redaction
# worked.
#
# Cleared in the same breath: this runs in the caller's shell, so a variable
# left defined here stays defined in it.  The status is expanded into the eval
# string before unset runs, so clearing it first costs nothing.
eval "unset __frf __frc; ( exit $__frc )"

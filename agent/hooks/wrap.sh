# shellcheck shell=bash
# Run one command with its output redacted.  Sourced, never executed:
#
#   source /usr/local/libexec/faramir/wrap.sh '<command>'
#
# faramir-guard rewrites every Bash tool call into that one line.  Three things
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
# is why the hook approves what its deny list did not refuse; see docs/scope.md.
#
# Redacted after the command finishes rather than through a pipe while it runs,
# because a pipeline puts the command in a subshell (losing the state again) and
# process substitution races: the shell moves on while the redactor is still
# writing, and whatever it had not written yet is lost.
#
# Every failure falls back to running the command and showing its output, never
# to running nothing or showing nothing.  A wrapper that breaks commands is a
# wrapper that gets removed, and a removed wrapper redacts nothing at all.

# /dev/shm before mktemp's own default: the file holds the command's output
# before redaction, so it belongs in memory rather than on a disk.  0600 either
# way, and removed as soon as it has been read.
__frf=$(mktemp "${XDG_RUNTIME_DIR:-/dev/shm}/faramir.XXXXXX" 2>/dev/null ||
  mktemp /dev/shm/faramir.XXXXXX 2>/dev/null || mktemp)

# ":;" keeps a comment-only command from forming an empty group.
# "${__frf:-/dev/stdout}" keeps an unwritable temp file from meaning the command
# does not run at all: redirecting to "" is an error the shell refuses.
{ :; eval "$1"
} >"${__frf:-/dev/stdout}" 2>&1
__frc=$?

# Redacted into a second file rather than straight to stdout, so that the
# fallback below can never append the unredacted copy to a partial redacted one.
# The fallback is what an install one version behind needs: a faramir without
# the redact subcommand prints usage and exits non-zero, and without it the
# command's real output would be discarded and every call would look like a
# silent success.  That second file holds redacted text, so /dev/shm again.
[ -n "$__frf" ] && {
  if "${FARAMIR_CLI:-/usr/local/bin/faramir}" redact <"$__frf" >"${__frf}.out"; then
    cat "${__frf}.out"
  else
    cat "$__frf"
  fi
  rm -f "$__frf" "${__frf}.out"
}

# Restores the command's own status, which is what the caller reads.
#
# Cleared in the same breath: this runs in the caller's shell, so a variable
# left defined here stays defined in it.  The status is expanded into the eval
# string before unset runs, so clearing it first costs nothing.
eval "unset __frf __frc; ( exit $__frc )"

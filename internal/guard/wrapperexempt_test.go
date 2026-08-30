package guard

import "testing"

// The rewrite emits `source <wrap.sh> '<command>'`, and the instructions tell an
// agent to use that form. The wrapper lives in the libexec directory, which is
// declared, so without an exemption the subject rule refuses every command the
// guard itself produces.
func TestTheWrapperInvocationIsLeftAlone(t *testing.T) {
	wrapper := wrapScript()
	for _, command := range []string{
		"source " + wrapper + " 'ls -la'",
		". " + wrapper + " 'ls -la'",
		"  source " + wrapper + " 'git status'",
	} {
		if pattern, denied := decide(command); denied {
			t.Errorf("%q is refused by %q, and it is the form the rewrite emits",
				command, pattern)
		}
	}
}

// The invocation is exempt, not the file. Deleting the wrapper turns off
// redaction for every Bash command on the host, and replacing it turns it into
// whatever the replacement does, so naming it any other way is answered by the
// subject rule as any other declared path is.
func TestTheWrapperItselfIsStillProtected(t *testing.T) {
	wrapper := wrapScript()
	for _, command := range []string{
		"rm " + wrapper,
		"echo x > " + wrapper,
		"sed -i s/a/b/ " + wrapper,
		"mv " + wrapper + " /tmp/x",
		"cat " + wrapper,
		"truncate -s 0 " + wrapper,
	} {
		if _, denied := decide(command); !denied {
			t.Errorf("%q is allowed, and it names the wrapper", command)
		}
	}
}

// Stripping the invocation must not take the command inside it with it: a
// wrapped command that reaches a declared path is still refused.
func TestAWrappedCommandIsStillRead(t *testing.T) {
	command := "source " + wrapScript() + " 'cat /etc/faramir/age.key'"
	if _, denied := decide(command); !denied {
		t.Error("a wrapped command naming a declared path is allowed, so the " +
			"exemption covers what it wraps rather than the wrapper")
	}
}

// Each command on a line is judged on its own, so the invocation is exempt
// wherever in a chain it sits. What that costs is nothing: sourcing the wrapper
// discloses no more than running it, which is the point of exempting it.
func TestTheInvocationIsExemptInAnySegment(t *testing.T) {
	command := "ls -l && source " + wrapScript() + " 'git status'"
	if pattern, denied := decide(command); denied {
		t.Errorf("%q is refused by %q, and each of its commands is ordinary",
			command, pattern)
	}
}

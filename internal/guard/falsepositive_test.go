package guard

import "testing"

// Words that happen to appear inside ordinary file names must not be read as
// the tools they name. "install" was in the write rule and matched
// verify-install.sh, so touching a script whose name contains it, anywhere near
// a faramir path, was refused. A rule that fires on a file name teaches the
// agent to reach for a tool the hook does not see, which is worse than the rule
// not existing.
func TestAToolNameInsideAFileNameIsNotTheTool(t *testing.T) {
	renderedFile(t)

	for _, cmd := range []string{
		"bash -n tests/verify-install.sh",
		"bash tests/verify-install.sh /home/op/.faramir",
		"grep -q pattern /usr/local/libexec/faramir/deny-patterns.txt",
		"ls -l /usr/local/libexec/faramir",
	} {
		if pattern, denied := decide(cmd); denied {
			t.Errorf("refused %q (pattern %q)", cmd, pattern)
		}
	}
}

// The writes those rules are for are still refused, with the verbs that remain.
func TestTheRemainingWriteVerbsStillRefuse(t *testing.T) {
	renderedFile(t)

	for _, cmd := range []string{
		"cp /bin/true /usr/local/libexec/faramir/wrap.sh",
		"tee /usr/local/libexec/faramir/deny-patterns.txt < /dev/null",
		"mv /etc/faramir/age.key /tmp/k",
		"rm -f /etc/faramir/secrets/x.sops.yml",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("did not refuse %q", cmd)
		}
	}
}

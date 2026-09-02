package hostsudo

// Reading a PAM stack.

import (
	"strings"
	"testing"
)

// The stack check reads position as well as the helper line: an auth entry
// ahead of it answers before the broker is asked, and requisite below gates
// nothing. Only the sudo-rs branch shape may stand ahead.
func TestPamStackProblemReadsWhatStandsAheadOfTheHelper(t *testing.T) {
	const helperLine = "auth requisite pam_exec.so quiet seteuid /usr/local/libexec/faramir/pam-escalate\n"
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"the rendered service", helperLine +
			"auth optional pam_env.so envfile=/x readenv=1\nauth sufficient pam_permit.so\n", ""},
		{"the sudo-rs block's branch stands ahead",
			"auth [success=ok default=3] pam_succeed_if.so quiet user = faramir-exec\n" + helperLine, ""},
		{"a permit ahead of the helper",
			"auth sufficient pam_permit.so\n" + helperLine, "ahead of the helper"},
		{"an include ahead of the helper",
			"@include common-auth\n" + helperLine, "@include ahead of the helper"},
		{"a sufficient succeed_if ahead is not the branch",
			"auth sufficient pam_succeed_if.so uid >= 0\n" + helperLine, "ahead of the helper"},
		{"requisite matched as a field, not a substring",
			"auth sufficient pam_exec.so quiet seteuid /opt/requisite-tool\n", "not `requisite`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := StackProblem(tc.body, "/usr/local/libexec/faramir/pam-escalate")
			if tc.want == "" && got != "" {
				t.Errorf("refused a sound stack: %s", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Errorf("problem = %q, want it to say %q", got, tc.want)
			}
		})
	}
}

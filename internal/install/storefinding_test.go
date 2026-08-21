package install

import (
	"strings"
	"testing"
)

// What the `secrets store` check makes of each state --check can report. An
// install keeping no managed file is valid: links fill the value set on their
// own, and a host that has not written its first secret is every install on its
// first day. What stays a failure is a file that is there and did not load.
func TestStoreFindingFailsOnlyOnSomethingWrong(t *testing.T) {
	const glob = "/etc/faramir/secrets/*.sops.yml"
	for _, tc := range []struct {
		name       string
		files      []string
		errors     []string
		unresolved []string
		patterns   []string
		count      int
		links      int
		want       Status
		says       string // a substring the detail has to carry
	}{
		{name: "a store holding refs",
			patterns: []string{glob}, files: []string{"a.sops.yml"}, count: 3,
			want: StatusOK, says: "3 ref(s)"},
		{name: "a store and links together",
			patterns: []string{glob}, files: []string{"a.sops.yml"}, count: 14, links: 1,
			want: StatusOK, says: "1 [[secret.link]] entry"},

		// The state the fleet hit: no store written, value set entirely linked.
		{name: "no managed file, one link",
			patterns: []string{glob}, unresolved: []string{glob}, count: 1, links: 1,
			want: StatusWarn, says: "the whole value set is 1 [[secret.link]] entry"},
		{name: "no managed file and nothing linked, a first install",
			patterns: []string{glob}, unresolved: []string{glob},
			want: StatusWarn, says: "nothing is served"},
		{name: "one pattern named nothing while another loaded",
			patterns: []string{glob, "/b/*.sops.yml"}, files: []string{"a.sops.yml"},
			unresolved: []string{"/b/*.sops.yml"}, count: 3,
			want: StatusWarn, says: "/b/*.sops.yml"},

		// Faults, which stay failures.
		{name: "a file that is there and did not load",
			patterns: []string{glob}, files: []string{"a.sops.yml"}, count: 3,
			errors: []string{"a.sops.yml: bad mac"},
			want:   StatusFailed, says: "bad mac"},
		{name: "a load error outranks a count, the daemon refusing either way",
			patterns: []string{glob}, files: []string{"a.sops.yml"}, count: 9, links: 1,
			errors: []string{"a.sops.yml: bad mac"}, want: StatusFailed},
		{name: "a file read that held no refs",
			patterns: []string{glob}, files: []string{"a.sops.yml"}, count: 0,
			want: StatusFailed, says: "loaded no refs"},
		{name: "nothing configured at all",
			want: StatusFailed, says: "nothing is injectable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c checkReport
			c.Secrets.Patterns = tc.patterns
			c.Secrets.Files = tc.files
			c.Secrets.Errors = tc.errors
			c.Secrets.UnresolvedPatterns = tc.unresolved
			c.Secrets.Count = tc.count
			c.Secrets.Links = tc.links
			status, detail := storeFinding(c)
			if status != tc.want {
				t.Errorf("status %q, want %q: %s", status, tc.want, detail)
			}
			if tc.says != "" && !strings.Contains(detail, tc.says) {
				t.Errorf("detail does not carry %q:\n%s", tc.says, detail)
			}
		})
	}
}

// A warning does not fail the run, which is the whole point: a configuration
// manager asserting on doctor's exit cannot converge a host it calls broken.
func TestAStoreWaitingForItsSecretsDoesNotFailTheRun(t *testing.T) {
	var c checkReport
	c.Secrets.Patterns = []string{"/etc/faramir/secrets/*.sops.yml"}
	c.Secrets.UnresolvedPatterns = c.Secrets.Patterns
	c.Secrets.Count, c.Secrets.Links = 1, 1

	var report DoctorReport
	status, detail := storeFinding(c)
	report.addf("secrets store", status, "%s", detail)
	if report.Failed {
		t.Errorf("a host serving its whole value set from links failed the run: %s", detail)
	}
}

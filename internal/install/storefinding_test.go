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
		says       []string // substrings the detail has to carry
	}{
		{name: "a store holding refs",
			patterns: []string{glob}, files: []string{"a.sops.yml"}, count: 3,
			want: StatusOK, says: []string{"3 ref(s)"}},
		{name: "a store and links together",
			patterns: []string{glob}, files: []string{"a.sops.yml"}, count: 14, links: 1,
			want: StatusOK, says: []string{"1 [[secret.link]] entry"}},

		// The state the fleet hit: no store written, value set entirely linked.
		{name: "no managed file, one link",
			patterns: []string{glob}, unresolved: []string{glob}, count: 1, links: 1,
			want: StatusWarn, says: []string{"the whole value set is 1 [[secret.link]] entry"}},
		{name: "no managed file and nothing linked, a first install",
			patterns: []string{glob}, unresolved: []string{glob},
			want: StatusWarn, says: []string{"nothing is injected and nothing is redacted"}},
		// The entry that named nothing is named, and what the entries that did
		// name something hold is reported beside it: the daemon serves this store,
		// so a detail saying nothing is served would be false.
		{name: "one pattern named nothing while another loaded",
			patterns: []string{glob, "/b/*.sops.yml"}, files: []string{"a.sops.yml"},
			unresolved: []string{"/b/*.sops.yml"}, count: 3, want: StatusWarn,
			says: []string{"/b/*.sops.yml", "3 ref(s) are served from 1 file(s)"}},
		// The file the other entry named opens the gate and held nothing, so the
		// ops are not refused and no value is covered either.
		{name: "one pattern named nothing, the file another named holding no ref",
			patterns: []string{glob, "/b/*.sops.yml"}, files: []string{"a.sops.yml"},
			unresolved: []string{"/b/*.sops.yml"}, count: 0, want: StatusWarn,
			says: []string{"1 file(s) loaded and held no ref"}},

		// Faults, which stay failures.
		{name: "a file that is there and did not load",
			patterns: []string{glob}, files: []string{"a.sops.yml"}, count: 3,
			errors: []string{"a.sops.yml: bad mac"},
			want:   StatusFailed, says: []string{"bad mac"}},
		{name: "a load error outranks a count, the daemon refusing either way",
			patterns: []string{glob}, files: []string{"a.sops.yml"}, count: 9, links: 1,
			errors: []string{"a.sops.yml: bad mac"}, want: StatusFailed},
		// An empty value set: the daemon serves these, so they warn.
		{name: "a file read that held no refs",
			patterns: []string{glob}, files: []string{"a.sops.yml"}, count: 0,
			want: StatusWarn, says: []string{"loaded no refs", "nothing is redacted"}},
		{name: "nothing configured at all",
			want: StatusWarn, says: []string{"nothing redacted"}},
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
			for _, says := range tc.says {
				if !strings.Contains(detail, says) {
					t.Errorf("detail does not carry %q:\n%s", says, detail)
				}
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

package install

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// The flag takes a path from the operator and what it names is copied into the
// account brokered commands run as, so a file that is not a known_hosts file is
// refused before anything is written rather than pinned as though it were one.
func TestReadKnownHostsCountsEntriesAndRefusesAnythingElse(t *testing.T) {
	const (
		ed25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExampleEx"
		ecdsa   = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBExampleExample"
	)
	for _, tc := range []struct {
		name string
		body string
		want int
		// refuses is what the error has to say, empty when the file is accepted.
		refuses string
	}{
		{
			name: "plain entries, comments and blank lines",
			body: "# the fleet\n\nhost.example.com ssh-ed25519 " + ed25519 +
				"\nhost.example.com ecdsa-sha2-nistp256 " + ecdsa + "\n",
			want: 2,
		},
		{
			// HashKnownHosts is on by default, so this is what most operators hold.
			name: "hashed entries",
			body: "|1|Zm9vYmFyYmF6cXV1eA==|cXV1eGZvb2Jhcg== ssh-ed25519 " + ed25519 + "\n",
			want: 1,
		},
		{
			// The name is qualified by the marker, so the key type is one field along.
			name: "markers and a bracketed port",
			body: "@cert-authority *.example.com ssh-ed25519 " + ed25519 +
				"\n@revoked [host.example.com]:2222 ssh-ed25519 " + ed25519 + "\n",
			want: 2,
		},
		{
			// Pins nothing, and is not an error: an empty file is a fleet not yet
			// collected, which the step warns about rather than refusing.
			name: "empty",
			body: "\n# nothing yet\n",
			want: 0,
		},
		{
			// The mistake that matters: a private key copied into an account that must
			// never hold one.
			name:    "a private key",
			body:    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n",
			refuses: "holds a private key",
		},
		{
			// Reversed fields: the key comes first, so nothing names a host.
			name:    "an authorized_keys file",
			body:    "ssh-ed25519 " + ed25519 + " operator@example.com\n",
			refuses: "line 1",
		},
		{
			name:    "an ssh config",
			body:    "Host *.example.com\n    User deploy\n",
			refuses: "line 1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_hosts")
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}

			data, entries, err := readKnownHosts(path)
			if tc.refuses != "" {
				if err == nil {
					t.Fatalf("accepted %s, which would be copied to the executor as host keys", tc.name)
				}
				if !strings.Contains(err.Error(), tc.refuses) {
					t.Errorf("refusal does not say %q: %v", tc.refuses, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused a known_hosts file: %v", err)
			}
			if entries != tc.want {
				t.Errorf("counted %d host key(s), want %d", entries, tc.want)
			}
			// Copied verbatim: what ssh reads has to be what the operator verified,
			// including the comments and the hashing.
			if string(data) != tc.body {
				t.Errorf("returned %q, want the file unchanged", data)
			}
		})
	}
}

// ssh reads a known_hosts file line by line and ignores what it cannot parse, so
// counting what it would take means counting past a bad line rather than
// rejecting the file: one hand edit in a file of two hundred must not be
// reported as a host that verifies nothing.
func TestCountKnownHostsCountsPastALineItCannotParse(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExample"
	dir := t.TempDir()
	mixed := filepath.Join(dir, "mixed")
	body := "one.example.com " + key + "\ntruncated.example.com ssh-ed\ntwo.example.com " + key + "\n"
	if err := os.WriteFile(mixed, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := countKnownHosts(mixed); got != 2 {
		t.Errorf("countKnownHosts = %d, want 2: the entries either side of a bad line "+
			"still verify their hosts", got)
	}
	// The strict read is a different question, asked of a path the operator named
	// before it is copied, and it still refuses the same file.
	if _, _, err := readKnownHosts(mixed); err == nil {
		t.Error("--known-hosts accepted a file with a line it could not parse")
	}
	if got := countKnownHosts(filepath.Join(dir, "absent")); got != 0 {
		t.Errorf("countKnownHosts(absent) = %d, want 0", got)
	}
}

// Without the flag nothing is written and nothing is reported: on the usual host
// /etc/ssh/ssh_known_hosts already covers every account, and a line on every
// install saying what was not done is noise.
func TestStepKnownHostsIsSilentWithoutTheFlag(t *testing.T) {
	run := &runner{layout: Layout{ExecUser: "faramir-exec"}, fs: fsys{dryRun: true}}

	if err := run.stepKnownHosts(); err != nil {
		t.Fatal(err)
	}
	if len(run.report.Steps) != 0 {
		t.Errorf("reported %v for an install that pinned nothing", run.report.Steps)
	}
}

// The count and both paths are reported, the operator otherwise having no way to
// see that what was pinned is what they named.
func TestStepKnownHostsReportsWhatWasPinnedAndFromWhere(t *testing.T) {
	source := filepath.Join(t.TempDir(), "known_hosts")
	body := "host.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExample\n"
	if err := os.WriteFile(source, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	run := &runner{
		layout:  Layout{ExecUser: "faramir-exec"},
		opts:    Options{KnownHosts: source, DryRun: true},
		fs:      fsys{dryRun: true},
		execUID: keep, execGID: keep,
	}

	if err := run.stepKnownHosts(); err != nil {
		t.Fatal(err)
	}
	if len(run.report.Steps) != 1 {
		t.Fatalf("reported %d steps, want 1", len(run.report.Steps))
	}
	detail := run.report.Steps[0].Detail
	for _, want := range []string{"/var/lib/faramir-exec/.ssh/known_hosts", "1 host key(s)", source} {
		if !strings.Contains(detail, want) {
			t.Errorf("step detail does not say %q: %s", want, detail)
		}
	}
	if len(run.report.Warnings) != 0 {
		t.Errorf("warned about a file that holds a host key: %v", run.report.Warnings)
	}
}

// The file is replaced whole, so pinning an empty one removes what an earlier run
// pinned. The warning has to say that: "pins none" reads as a write that changed
// nothing, and the fleet is unreachable either way.
func TestStepKnownHostsWarnsWhenTheFilePinsNothing(t *testing.T) {
	source := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(source, []byte("# collected nothing yet\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := &runner{
		layout:  Layout{ExecUser: "faramir-exec"},
		opts:    Options{KnownHosts: source, DryRun: true},
		fs:      fsys{dryRun: true},
		execUID: keep, execGID: keep,
	}

	if err := run.stepKnownHosts(); err != nil {
		t.Fatal(err)
	}
	warnings := strings.Join(run.report.Warnings, "\n")
	if !strings.Contains(warnings, "removes whatever") {
		t.Errorf("warned about an empty file without saying it removes what was "+
			"pinned: %v", run.report.Warnings)
	}
	if !strings.Contains(warnings, globalKnownHosts) {
		t.Errorf("warning does not name what is left verifying the fleet: %s", warnings)
	}
}

// The executor's file is inside a 0700 home, so without root the answer is
// unknown rather than none, and it counts against what doctor did not ask.
func TestDiagnoseKnownHostsDoesNotGuessWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads the executor's home, so the check is answered rather than skipped")
	}
	var report DoctorReport
	cfg := &config.Config{}
	cfg.Ssh.Key = "/etc/faramir/id_ed25519"

	diagnoseKnownHosts(&report, DoctorOptions{ExecUser: "faramir-exec"}, cfg)

	if report.NotAsked != 1 {
		t.Errorf("NotAsked = %d, want 1: an unanswered check is not a passing one", report.NotAsked)
	}
	if len(report.Findings) != 1 || report.Findings[0].Status != StatusWarn {
		t.Fatalf("findings = %+v, want one warning", report.Findings)
	}
	if !strings.Contains(report.Findings[0].Detail, "/var/lib/faramir-exec/.ssh/known_hosts") {
		t.Errorf("does not name the file it could not read: %s", report.Findings[0].Detail)
	}
}

// A host that authenticates some other way has no key and no host keys to hold,
// so nothing is reported: doctor answers for what was installed.
func TestDiagnoseKnownHostsSaysNothingWithoutAKey(t *testing.T) {
	var report DoctorReport

	diagnoseKnownHosts(&report, DoctorOptions{ExecUser: "faramir-exec"}, &config.Config{})

	if len(report.Findings) != 0 {
		t.Errorf("reported %+v for a host with no [ssh] key", report.Findings)
	}
}

// The three ways --known-hosts names the wrong file, asked where the answer
// costs nothing. stepKnownHosts runs after the age key, the sops rule, the
// binary, the config and the SSH key are written, so the same refusal raised
// there is a host part way provisioned for a path typed wrong.
func TestKnownHostsIsJudgedBeforeAnythingIsWritten(t *testing.T) {
	dir := t.TempDir()
	privateKey := filepath.Join(dir, "the-key-beside-it")
	if err := os.WriteFile(privateKey,
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nnot a real one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prose := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(prose, []byte("just some prose\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, path, wantErr string }{
		{"a file that is not there", filepath.Join(dir, "gone"), "no such file"},
		{"the private key rather than the host keys", privateKey, "holds a private key"},
		{"a file that is not known_hosts at all", prose, "is not a known_hosts entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Through preflight rather than the reader it calls, so what this
			// holds is that the refusal comes before anything is written: a test
			// against the reader alone passes however late it is asked.
			run := &runner{opts: Options{KnownHosts: tc.path, DryRun: true,
				AgentUser: currentUserName(t)}}

			err := run.preflight()

			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), "--known-hosts") {
				t.Errorf("the refusal does not name the flag: %v", err)
			}
		})
	}

	// Naming none is not a refusal: the option is optional, and leaving it out
	// keeps whatever the executor already has pinned.
	run := &runner{opts: Options{DryRun: true, AgentUser: currentUserName(t)}}
	if err := run.preflight(); err != nil && strings.Contains(err.Error(), "--known-hosts") {
		t.Errorf("no --known-hosts was refused: %v", err)
	}
}

// currentUserName is an account preflight will accept: it must exist and must
// not be root, and a dry run is what lets the rest of preflight be reached
// without being root.
func currentUserName(t *testing.T) string {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	if me.Username == "root" {
		t.Skip("preflight refuses root as the agent account")
	}
	return me.Username
}

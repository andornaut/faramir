package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A group's members are not only what /etc/group lists.  An account whose
// PRIMARY group this is holds it without appearing there, and that is the shape
// a renamed --keeper-user leaves behind: the secrets group defaults to the
// keeper's own group, so reading the member list alone reports the one case
// worth reporting as clean.
func TestPrimaryMembersFindsWhatGroupDoesNot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	body := "root:x:0:0::/root:/bin/sh\n" +
		"faramir-keeper:x:996:995::/var/lib/faramir-keeper:/usr/sbin/nologin\n" +
		"faramir-keeper2:x:993:992::/var/lib/faramir-keeper2:/usr/sbin/nologin\n" +
		"operator:x:1000:1000::/home/operator:/bin/bash\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	passwdFile = path
	t.Cleanup(func() { passwdFile = "/etc/passwd" })

	got, err := primaryMembers("995")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "faramir-keeper" {
		t.Errorf("the retired keeper holds gid 995 as its primary group and was not "+
			"found: %v", got)
	}
	if members, err := primaryMembers("1"); err != nil || len(members) != 0 {
		t.Errorf("a group nobody holds should be empty: %v, %v", members, err)
	}
}

// The retired accounts a re-run leaves behind are a standing grant, and nothing
// on the host reported them: changing --client-group leaves the old group with
// every member, and renaming --keeper-user leaves the retired account in the
// group that owns the ciphertext.  init does not take memberships away, so
// doctor has to name them.
func TestDiagnoseGroupNamesAccountsTheInstallNoLongerUses(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	// The retired keeper holds the secrets group as its primary group, which is
	// what /etc/group will not show.
	if err := os.WriteFile(passwd, []byte(
		"retired-keeper:x:996:995::/var/lib/retired-keeper:/usr/sbin/nologin\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	passwdFile = passwd
	t.Cleanup(func() { passwdFile = "/etc/passwd" })

	group := filepath.Join(dir, "group")
	if err := os.WriteFile(group, []byte(
		"faramir-keeper:x:995:faramir-keeper2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	groupFile = group
	t.Cleanup(func() { groupFile = "/etc/group" })

	var report DoctorReport
	diagnoseGroupOutsiders(&report, "secrets group", "faramir-keeper",
		[]string{"operator", "faramir-broker", "faramir-keeper2", "faramir-exec"},
		"read the ciphertext")
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %v", report.Findings)
	}
	finding := report.Findings[0]
	if finding.Status != StatusWarn {
		t.Errorf("a retired account holding the secrets group is a standing grant, "+
			"reported as %s: %s", finding.Status, finding.Detail)
	}
	for _, want := range []string{"retired-keeper", "gpasswd -d", "usermod -g"} {
		if !strings.Contains(finding.Detail, want) {
			t.Errorf("the finding does not mention %q: %s", want, finding.Detail)
		}
	}
}

// doctor reached without SUDO_USER — a root shell, a cron entry, a
// configuration manager — cannot name the operator.  canRead and canWrite then
// answer false, which is the same answer a boundary that holds gives, so the
// checks that pass become unearned OKs and the ones that run a command fail
// blaming a `runuser -u --` nobody wrote.  Neither is a finding about the host.
func TestBoundariesAreNotAskedWithoutAnOperator(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the no-root guard answers first when this is not root")
	}
	// Accounts that exist, so the runuser probe passes and the checks are actually
	// reached.  root stands in for every role here; what is under test is which
	// checks run, not what they find.
	var report DoctorReport
	diagnoseBoundaries(&report, DoctorOptions{
		BrokerUser: "root", KeeperUser: "root", ExecUser: "root", ClientGroup: "root",
	}, nil, servesUnknown)

	boundaries := findingsNamed(report, "boundaries")
	if len(boundaries) != 1 {
		t.Fatalf("expected one warn standing for the operator checks, got %v", report.Findings)
	}
	if boundaries[0].Status != StatusWarn {
		t.Errorf("an unnamed operator is a question that cannot be put, not a "+
			"verdict: %v", boundaries[0])
	}
	if report.NotAsked == 0 {
		t.Error("the unasked checks were not counted, so the totals read as a " +
			"complete examination")
	}
	for _, want := range []string{"--operator-user", "SUDO_USER"} {
		if !strings.Contains(boundaries[0].Detail, want) {
			t.Errorf("the warning does not say how to fix it (%q): %s",
				want, boundaries[0].Detail)
		}
	}
	// The point of the split: the checks that never ask about the operator have to
	// keep running, or a root shell reports a clean host having examined nothing.
	if len(report.Findings) < 2 {
		t.Errorf("no check ran besides the warning, so an age key left 0644 or a "+
			"regrouped socket would go unreported: %v", report.Findings)
	}
	// And nothing may claim a boundary it could not ask about.
	for _, finding := range report.Findings {
		if finding.Status == StatusOK && strings.Contains(finding.Detail, "operator") {
			t.Errorf("a check claimed something about an operator it cannot name: %v",
				finding)
		}
	}
}

// findingsNamed is the findings one check contributed.
func findingsNamed(report DoctorReport, name string) []Finding {
	var out []Finding
	for _, finding := range report.Findings {
		if finding.Name == name {
			out = append(out, finding)
		}
	}
	return out
}

// The client group check cannot tell a member from a leftover without the
// operator's name, and the operator IS a member by construction.  Reporting it
// as a leftover prints `gpasswd -d <operator> <client group>` as the remedy,
// which is the one change that shuts the agent out of the broker socket.
func TestTheGroupAuditIsNotAskedWithoutAnOperator(t *testing.T) {
	dir := t.TempDir()
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(group, []byte("dev:x:1000:alice,faramir-exec\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	groupFile = group
	t.Cleanup(func() { groupFile = "/etc/group" })

	var report DoctorReport
	diagnoseGroup(&report, DoctorOptions{
		ClientGroup: "dev", BrokerUser: "faramir-broker",
		KeeperUser: "faramir-keeper", ExecUser: "faramir-exec",
	})
	if len(report.Findings) != 1 || report.Findings[0].Status != StatusWarn {
		t.Fatalf("expected the audit to be reported unasked, got %v", report.Findings)
	}
	if strings.Contains(report.Findings[0].Detail, "gpasswd -d") {
		t.Errorf("an unnamed operator was handed a remedy that would shut the agent "+
			"out of the broker socket: %s", report.Findings[0].Detail)
	}
}

// asUser is what turned an unnamed account into "runuser: user does not exist",
// reported as a boundary that does not hold.  Guarded at the source so a new
// caller cannot reintroduce it.
func TestAsUserRefusesAnUnnamedAccount(t *testing.T) {
	if _, err := asUser("", "true"); err == nil {
		t.Fatal("an empty account was passed to runuser, which reads it as the " +
			"account name and fails with a message about the host")
	}
}

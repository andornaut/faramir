package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A group's members are not only what /etc/group lists. An account whose
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
// group that owns the ciphertext. init does not take memberships away, so
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

	var report Report
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

// The client group check cannot tell a member from a leftover without the
// operator's name, and the operator IS a member by construction. Reporting it
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

	var report Report
	diagnoseGroup(&report, Options{
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

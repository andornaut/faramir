package install

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/secretlink"
)

// linksFor is one text link per path, which is all the grant step reads.
func linksFor(paths []string) []config.Link {
	out := make([]config.Link, 0, len(paths))
	for i, path := range paths {
		out = append(out, config.Link{
			Ref: "test/" + strconv.Itoa(i), Path: path, Type: secretlink.KindText,
		})
	}
	return out
}

// secondGroup is a group this account is in other than its primary, so a test
// can move a file into one without root.
func secondGroup(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	if err != nil {
		t.Skipf("cannot read this account's groups: %v", err)
	}
	for _, candidate := range groups {
		if candidate != os.Getgid() {
			return candidate
		}
	}
	t.Skip("this account has no second group to grant with")
	return -1
}

// linkRunner is an install run that grants access to the paths given, with the
// caller's own second group standing in for the broker's.
//
// The paths a test hands it are under t.TempDir, outside every home, which is
// where sharetree.Reachable stops: the file grant is what these exercise, and
// the traversal grant has its own tests.
func linkRunner(t *testing.T, gid int, paths ...string) *runner {
	t.Helper()
	current, err := osuser.Current()
	if err != nil {
		t.Skipf("cannot name this account: %v", err)
	}
	group, err := osuser.LookupGroupId(current.Gid)
	if err != nil {
		t.Skipf("cannot name this account's group: %v", err)
	}
	return &runner{
		opts:      Options{AgentUser: current.Username, links: linksFor(paths), linksSet: true},
		layout:    Layout{BrokerUser: "faramir-broker", ClientGroup: group.Name},
		brokerGID: gid,
	}
}

func TestALinkedFileBecomesReadableByTheBrokersGroup(t *testing.T) {
	gid := secondGroup(t)
	path := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.WriteFile(path, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := linkRunner(t, gid, path).stepLinkAccess(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("mode = %o, want 640", got)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("cannot read ownership")
	}
	if int(stat.Gid) != gid {
		t.Errorf("gid = %d, want %d", stat.Gid, gid)
	}
	// The owner is left alone: the file is the operator's and their tool
	// rewrites it.
	if int(stat.Uid) != os.Getuid() {
		t.Errorf("uid = %d, want the owner left at %d", stat.Uid, os.Getuid())
	}
}

// Only what the broker needs. A file the operator keeps unwritable stays that
// way, and nothing is granted to other.
func TestALinkedFilesOwnerBitsAreKept(t *testing.T) {
	gid := secondGroup(t)
	path := filepath.Join(t.TempDir(), "keyfile")
	if err := os.WriteFile(path, []byte("token\n"), 0o400); err != nil {
		t.Fatal(err)
	}

	if err := linkRunner(t, gid, path).stepLinkAccess(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o440 {
		t.Errorf("mode = %o, want 440: the owner's bits kept and group read added", got)
	}
}

// A credential that has left the machine, or a home not mounted yet. The
// broker reports it per request; the install does not refuse to finish.
func TestAnAbsentLinkedFileDoesNotStopTheInstall(t *testing.T) {
	gid := secondGroup(t)
	run := linkRunner(t, gid, filepath.Join(t.TempDir(), "gone.yml"))
	if err := run.stepLinkAccess(); err != nil {
		t.Fatalf("an absent linked file stopped the install: %v", err)
	}
}

// The grant would land on the target rather than the link.
func TestALinkedSymlinkIsRefused(t *testing.T) {
	gid := secondGroup(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "link.yml")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	err := linkRunner(t, gid, path).stepLinkAccess()
	if err == nil {
		t.Fatal("a symlinked linked file was accepted")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	// The target is untouched, the refusal having come first.
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("the target's mode became %o", got)
	}
}

func TestLinkAccessIsSkippedWithNoLinks(t *testing.T) {
	run := &runner{}
	if err := run.stepLinkAccess(); err != nil {
		t.Fatal(err)
	}
}

// -- the doctor check -------------------------------------------------------

func TestDoctorLinkedAccessSaysSoWhenNothingIsLinked(t *testing.T) {
	var report DoctorReport
	diagnoseLinkedAccess(&report, DoctorOptions{}, &config.Config{})

	finding := findingFor(t, report, "linked file access")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK: %s", finding.Status, finding.Detail)
	}
}

// canRead answers false for an account it cannot name, which is what it
// answers for one that is properly shut out, so an unnamed account is not a
// pass and not a failure.
func TestDoctorLinkedAccessIsUnaskedWithoutBothAccounts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Secret.Links = []config.Link{{Ref: "gh/token", Path: "/nowhere"}}
	var report DoctorReport
	diagnoseLinkedAccess(&report, DoctorOptions{BrokerUser: "faramir-broker"}, cfg)

	finding := findingFor(t, report, "linked file access")
	if finding.Status == StatusOK || finding.Status == StatusFailed {
		t.Errorf("status = %v, want neither a pass nor a verdict: %s",
			finding.Status, finding.Detail)
	}
	if !strings.Contains(finding.Detail, "not asked") {
		t.Errorf("the finding does not say the question went unasked: %s", finding.Detail)
	}
}

// The step list has to resolve the agents before it writes their files.
// stepAgentConfig reads what stepPreconditions puts in r.agentTargets, and a
// list without it writes no deny rule while reporting that it found no agent.
func TestLinkStepsResolveTheAgentsBeforeWritingThem(t *testing.T) {
	steps := (&runner{}).LinkSteps()
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.name)
	}
	preconditions := slices.Index(names, "preconditions")
	agentConfig := slices.Index(names, "agent config")
	if preconditions < 0 {
		t.Fatalf("steps = %v, want preconditions among them", names)
	}
	if agentConfig < 0 || preconditions > agentConfig {
		t.Errorf("steps = %v, want preconditions before agent config", names)
	}
}

// Adding a link rewrites the whole of config.toml, and the sudo grant is not
// adopted from anywhere: without this, `link add` on a host installed with
// --allow-sudo would drop [escalation] and leave the sudoers entry and PAM service
// naming a broker that no longer names them.
func TestALinkOperationKeepsTheSudoGrant(t *testing.T) {
	dir := t.TempDir()
	body := "[command]\ntimeout_sec = 600\n\n[escalation]\nexec_user = \"faramir-exec\"\n" +
		"notify_command = [\"/usr/bin/wall\", \"{prompt}\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := Options{}
	if err := keepInstalledGrant(&opts, dir); err != nil {
		t.Fatal(err)
	}
	if !opts.AllowSudo {
		t.Error("the sudo grant was not kept, so rewriting the config would remove it")
	}
	if !slices.Equal(opts.NotifyCommand, []string{"/usr/bin/wall", "{prompt}"}) {
		t.Errorf("notify_command = %v, want the installed one", opts.NotifyCommand)
	}
}

// A host with no grant keeps none: this preserves what is installed, it does
// not turn anything on.
func TestALinkOperationGrantsNoSudoOfItsOwn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"),
		[]byte("[command]\ntimeout_sec = 600\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{}
	if err := keepInstalledGrant(&opts, dir); err != nil {
		t.Fatal(err)
	}
	if opts.AllowSudo {
		t.Error("a host with no grant was given one")
	}
}

// A config.d beside the file is no longer read at all, so a link written there
// is not a link.  The one file is the whole of it.
func TestADropInIsNotRead(t *testing.T) {
	dir := t.TempDir()
	base := "[command]\ntimeout_sec = 600\n\n[[secret.link]]\n" +
		"ref = \"gh/token\"\npath = \"/home/operator/.config/gh/hosts.yml\"\n" +
		"type = \"yaml\"\nkey = \"github.com/oauth_token\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	dropIn := "[[secret.link]]\nref = \"npm/token\"\npath = \"/home/operator/.npmrc\"\n" +
		"type = \"ini\"\nkey = \"//registry.npmjs.org/:_authToken\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.d", "10-npm.toml"),
		[]byte(dropIn), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := Options{ConfigDir: dir}
	if _, err := opts.adoptInstalled(); err != nil {
		t.Fatal(err)
	}
	if len(opts.links) != 1 || opts.links[0].Ref != "gh/token" {
		t.Errorf("links = %+v, want the one the config file declares", opts.links)
	}
}

// The guard the [escalation] bug asked for.
//
// `link add` rewrites the whole of config.toml from the layout it builds, so
// every value that file carries has to survive the round trip through the
// install and back.  One that does not is not a diff anybody sees: it is a
// section quietly dropped from a running host, which is what happened to the
// sudo grant.
//
// So: render the file as an install would, then rebuild the options the way a
// link operation does, render again, and hold the two to being identical.  A
// value rendered into config.toml and recoverable from nothing fails here
// rather than on somebody's host.
func TestALinkOperationRendersTheSameConfigTheInstallDid(t *testing.T) {
	dir := t.TempDir()
	installed := Options{
		ConfigDir: dir,
		AgentUser: "operator",
		// Deliberately not the defaults: a value that matches the compiled-in one
		// would round-trip whether it was recovered or not.
		ClientGroup:   "devs",
		SSHKey:        filepath.Join(dir, "custom_ed25519"),
		AllowSudo:     true,
		NotifyCommand: []string{"/usr/bin/wall", "{prompt}"},
	}
	installed.applyDefaults()
	installed.links, installed.linksSet = []config.Link{{
		Ref: "gh/token", Path: "/home/operator/.config/gh/hosts.yml",
		Type: "yaml", Key: "github.com/oauth_token",
	}}, true
	layout, err := installed.layout()
	if err != nil {
		t.Fatal(err)
	}
	first, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), first, 0o600); err != nil {
		t.Fatal(err)
	}

	// What AddLink and RemoveLink build, against nothing but the installed file.
	next := Options{ConfigDir: dir, AgentUser: "operator"}
	if err := keepInstalledGrant(&next, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := next.adoptInstalled(); err != nil {
		t.Fatal(err)
	}
	next.applyDefaults()
	nextLayout, err := next.layout()
	if err != nil {
		t.Fatal(err)
	}
	second, err := render("etc/config.toml.tmpl", nextLayout)
	if err != nil {
		t.Fatal(err)
	}

	if string(first) != string(second) {
		t.Errorf("a link operation would rewrite config.toml differently from the "+
			"install that wrote it, so something in this file is derived and not "+
			"recovered:\n--- installed\n%s\n--- after a link operation\n%s", first, second)
	}
}

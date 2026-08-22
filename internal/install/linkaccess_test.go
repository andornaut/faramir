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

// linkRunner is an install run that checks the paths given, with the caller's
// own second group standing in for the broker's.
//
// The paths a test hands it are under t.TempDir, outside every home, which is
// where sharetree.Traversable stops: the file's own ownership and mode are what
// these exercise, and the directories above it have their own tests.
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

// The arrangement a link needs is reported and not applied: faramir does not
// change the ownership or mode of a file it does not own.
func TestALinkedFileTheBrokerCannotReadIsReported(t *testing.T) {
	gid := secondGroup(t)
	path := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.WriteFile(path, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := linkRunner(t, gid, path).stepLinkAccess()
	if err == nil {
		t.Fatal("a linked file the broker cannot read was accepted")
	}
	// The command that fixes it, so whoever reads this does not have to work out
	// which of the two is wrong.
	for _, want := range []string{"chgrp", "chmod g+r", path} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}

	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600: the check altered the file", got)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("cannot read ownership")
	}
	if int(stat.Gid) != os.Getgid() {
		t.Errorf("gid = %d, want %d: the check regrouped the file", stat.Gid, os.Getgid())
	}
}

// A file already arranged the way a link needs passes, and is left alone.
func TestALinkedFileAlreadyReadableIsAccepted(t *testing.T) {
	gid := secondGroup(t)
	path := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.WriteFile(path, []byte("token\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, -1, gid); err != nil {
		t.Skipf("cannot regroup a file into %d: %v", gid, err)
	}

	if err := linkRunner(t, gid, path).stepLinkAccess(); err != nil {
		t.Fatalf("a linked file the broker can read was refused: %v", err)
	}
}

// Group read for the broker is the whole grant. A file other can read is one
// every account on the host reads, the executor included, and no mode on the
// broker's group changes that.
func TestAWorldReadableLinkedFileIsReported(t *testing.T) {
	gid := secondGroup(t)
	path := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.WriteFile(path, []byte("token\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, -1, gid); err != nil {
		t.Skipf("cannot regroup a file into %d: %v", gid, err)
	}

	err := linkRunner(t, gid, path).stepLinkAccess()
	if err == nil {
		t.Fatal("a world-readable linked file was accepted")
	}
	if !strings.Contains(err.Error(), "chmod o-r") {
		t.Errorf("the refusal does not name what narrows it: %v", err)
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

// A link names the file that holds the value, and what a symlink says about
// ownership and mode is the target's.
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

// The refusal above, with a good link ahead of the bad one. Nothing is altered
// either way, so what this holds to is that a run which refuses one entry has
// not touched another.
func TestARefusedLinkLeavesTheOthersUntouched(t *testing.T) {
	gid := secondGroup(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "hosts.yml")
	if err := os.WriteFile(good, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "link.yml")
	if err := os.Symlink(target, bad); err != nil {
		t.Fatal(err)
	}

	// The good one first, so a loop that grants as it goes would have granted it
	// by the time it met the symlink.
	err := linkRunner(t, gid, good, bad).stepLinkAccess()
	if err == nil {
		t.Fatal("a symlinked linked file was accepted")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	info, statErr := os.Stat(good)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("the accepted link's mode became %o, want 600, untouched", got)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("cannot read ownership")
	}
	if int(stat.Gid) != os.Getgid() {
		t.Errorf("the accepted link was regrouped to gid %d, want %d, untouched",
			stat.Gid, os.Getgid())
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
// is not a link. The one file is the whole of it.
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

// `link add` rewrites the whole of config.toml from the layout it builds, so
// every value that file carries has to survive the round trip through the
// install and back. A value that does not is not a visible diff: it is a
// section dropped from a running host.
//
// Render the file as an install would, rebuild the options the way a link
// operation does, render again, and hold the two to being identical.
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

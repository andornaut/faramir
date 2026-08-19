package install

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/config"
)

// globalKnownHosts is the file ssh consults before any account's own, so one
// copy answers for the executor, the operator and root at once.  Root-owned and
// outside every home, which makes it the arrangement to prefer.
const globalKnownHosts = "/etc/ssh/ssh_known_hosts"

// knownHostsKeyTypes are the algorithm prefixes a host key line can carry.
// Prefixes rather than an exact list: a type a later OpenSSH adds is still a
// host key.
var knownHostsKeyTypes = []string{"ssh-", "ecdsa-", "sk-", "webauthn-"}

// readKnownHosts reads a known_hosts file and reports how many host keys it
// holds, refusing a file that is not one: what the flag names is copied into an
// account that must never hold key material.
func readKnownHosts(path string) ([]byte, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		return nil, 0, fmt.Errorf("%s holds a private key. This takes the public "+
			"host keys ssh verifies a host against, which is ~/.ssh/known_hosts", path)
	}
	entries, bad := parseKnownHosts(data)
	if bad != 0 {
		return nil, 0, fmt.Errorf("%s line %d is not a known_hosts entry, which is "+
			"a host name, a key type and a key. Check the path names the right file", path, bad)
	}
	return data, entries, nil
}

// parseKnownHosts counts the host key entries in a known_hosts file and reports
// the first line that is not one, zero when every line parses.  Blank lines and
// comments are neither.
func parseKnownHosts(data []byte) (entries, bad int) {
	for i, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		// @cert-authority and @revoked qualify the name that follows them.
		if strings.HasPrefix(fields[0], "@") {
			fields = fields[1:]
		}
		// A hashed entry is still name, type and key; only the name is opaque.
		if len(fields) < 3 || !hasPrefixIn(fields[1], knownHostsKeyTypes) {
			if bad == 0 {
				bad = i + 1
			}
			continue
		}
		entries++
	}
	return entries, bad
}

func hasPrefixIn(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// countKnownHosts reports how many host keys ssh would take from a file, and
// zero for one that is absent.  Lenient where readKnownHosts refuses: ssh
// ignores a line it cannot parse, so the entries either side of a bad one still
// verify their hosts.
func countKnownHosts(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	entries, _ := parseKnownHosts(data)
	return entries
}

// stepKnownHosts pins the host keys a brokered ssh verifies against.
//
// A copy rather than a reference: the executor cannot read the operator's 0700
// ~/.ssh, and ssh names no environment variable for a known_hosts file.  Safe
// where copying an ssh config is not, a known_hosts file being public keys with
// no directive that executes anything.  Silent without --known-hosts.
//
// Replaced whole rather than merged: HashKnownHosts is on by default, so
// entries cannot be matched by name, and appending blind would keep a rotated
// host's old key as a second line ssh still accepts.
func (r *runner) stepKnownHosts() error {
	if r.opts.KnownHosts == "" {
		return nil
	}
	data, entries, err := readKnownHosts(r.opts.KnownHosts)
	if err != nil {
		return err
	}
	path := r.layout.ExecKnownHosts()
	// The file is replaced whole, so pinning an empty one removes what is
	// there.
	if entries == 0 {
		r.warnf("%s holds no host keys, so this removes whatever %s had pinned and "+
			"leaves a brokered ssh verifying against %s alone. Re-run with a file that "+
			"holds the fleet's host keys, or leave --known-hosts out to keep what is pinned",
			r.opts.KnownHosts, path, globalKnownHosts)
	}
	// A dry run runs unprivileged and cannot look inside the executor's 0700
	// home.  Reported as a change, which does not call an install current when it
	// is not.
	if r.opts.DryRun {
		r.step("known hosts", true, fmt.Sprintf("pin %d host key(s) from %s in %s",
			entries, r.opts.KnownHosts, path))
		return nil
	}
	// Created by the accounts step; asserted here so a run after it was removed
	// by hand writes into a directory with the mode it needs.
	made, err := r.fs.ensureDir(filepath.Dir(path), 0o700, r.execUID, r.execGID, true)
	if err != nil {
		return err
	}
	// World-readable like the other public halves this installs, and the
	// executor's own: the home above it is 0700.
	changed, err := r.fs.writeFile(path, data, 0o644, r.execUID, r.execGID)
	if err != nil {
		return err
	}
	r.step("known hosts", changed || made,
		fmt.Sprintf("%s, %d host key(s) from %s", path, entries, r.opts.KnownHosts))
	return nil
}

// diagnoseKnownHosts reports what a brokered ssh can verify a host against.
// ssh reads the global file before the account's own, so either holding entries
// is enough and the counts are reported together.
//
// Never a failure: nothing pinned is what a host with no fleet looks like, and
// a host may arrange verification some other way.  Reported because the state
// is otherwise silent until a playbook hits it.  Needs root, the executor's
// file being inside a 0700 home.
func diagnoseKnownHosts(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	if cfg == nil || cfg.Ssh.Key == "" {
		return
	}
	layout := Layout{ExecUser: opts.ExecUser}
	path := layout.ExecKnownHosts()
	if os.Geteuid() != 0 {
		report.unaskedf("known hosts", 1, "not asked: reading %s needs root, "+
			"the executor's home being 0700", path)
		return
	}
	// Counted as root and read as the executor, which are different questions:
	// root's mode bypass reads a file the account that runs the command cannot.
	own, global := 0, 0
	unreadable := []string{}
	for _, file := range []struct {
		path  string
		count *int
	}{{globalKnownHosts, &global}, {path, &own}} {
		if !exists(file.path) {
			continue
		}
		if !canRead(opts.ExecUser, file.path) {
			unreadable = append(unreadable, file.path)
			continue
		}
		*file.count = countKnownHosts(file.path)
	}
	// An unreadable file is named rather than failed on: the other may hold the
	// whole fleet.
	ignored := ""
	if len(unreadable) > 0 {
		ignored = fmt.Sprintf(". %s cannot read %s, so nothing in it verifies anything; "+
			"sudo chmod a+r %s", opts.ExecUser, strings.Join(unreadable, " or "),
			strings.Join(unreadable, " "))
	}
	if own+global == 0 {
		report.addf("known hosts", StatusOK, "neither %s nor %s holds a host key the "+
			"executor can read, so a brokered ssh refuses a managed host before the "+
			"broker's key is offered. Pin them with `init --known-hosts`, or write %s, "+
			"which every account reads%s", globalKnownHosts, path, globalKnownHosts, ignored)
		return
	}
	report.addf("known hosts", StatusOK, "%d host key(s) a brokered ssh verifies against "+
		"(%d in %s, %d in %s)%s", own+global, global, globalKnownHosts, own, path, ignored)
}

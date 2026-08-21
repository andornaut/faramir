package install

import (
	"os"
	"path/filepath"
	"strings"
)

// What a bare default costs, reported rather than enforced.
//
// faramir refuses what it installs and nothing else, so a credential of the
// operator's own is refused once they name it and not before. That is the right
// default: a rule for a file this install did not write is a guess about
// somebody else's machine, and a wrong guess costs the agent access to work it
// should be doing.
//
// It is the wrong default for a list nobody ever writes, though, and an
// accident filter with nothing in it catches nothing. So the list lives here
// instead, and reports. The register is what changes: a guess that refuses has
// to be right, and a guess that names a file it found and offers a command is
// useful even when it is wrong, because the operator is the one deciding.
//
// Never opened. Every path here is stat'ed and named, and the check says
// nothing about what is in one.

// wellKnownCredentials is where tools keep a credential in the operator's home.
// Broad on purpose, and safe to be broad: a name here that this machine does
// not use is a line that never prints.
var wellKnownCredentials = []string{
	".ssh/id_rsa",
	".ssh/id_dsa",
	".ssh/id_ecdsa",
	".ssh/id_ed25519",
	".config/sops/age/keys.txt",
	".aws/credentials",
	".config/gh/hosts.yml",
	".config/gcloud/credentials.db",
	".docker/config.json",
	".kube/config",
	".npmrc",
	".netrc",
	".pgpass",
	".cargo/credentials.toml",
	".gnupg",
	".password-store",
}

// diagnoseUnrefusedCredentials names what is in the agent account's home and
// refused by nothing. A warning, never a failure: what a machine should refuse
// is the operator's to decide, and a host that has decided is not broken.
func diagnoseUnrefusedCredentials(report *DoctorReport, opts DoctorOptions) {
	const name = "unrefused credentials"
	if opts.AgentUser == "" {
		report.unaskedf(name, 1, "the agent account is not named, so its home was "+
			"not looked at: pass --agent-user, or run through sudo so SUDO_USER "+
			"carries it")
		return
	}
	home, err := agentHomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf(name, 1, "could not read %s's home, so what is in it and "+
			"refused by nothing went unchecked", opts.AgentUser)
		return
	}
	layout := ruleLayout(opts.ConfigDir)
	var found []string
	for _, rel := range wellKnownCredentials {
		path := filepath.Join(home, rel)
		if !exists(path) {
			continue
		}
		if _, covered := RefusedBy(layout, path); covered {
			continue
		}
		found = append(found, path)
	}
	if len(found) == 0 {
		report.addf(name, StatusOK, "every credential this looks for in %s's home "+
			"is either absent or refused", opts.AgentUser)
		return
	}
	report.addf(name, StatusWarn, "%d file(s) in %s's home are refused by nothing, "+
		"so the agent's file tools may open them and a command may print them: %s. "+
		"faramir refuses what it installs and leaves the rest to you; name these, "+
		"or the ones that matter, with `sudo faramir refuse add %s`",
		len(found), opts.AgentUser, strings.Join(found, ", "), suggestFor(found))
}

// suggestFor is the command that would refuse what was found, by name where a
// name is what the operator would want and by path otherwise. Names, because a
// rule for one machine's ~/.ssh/id_rsa is a rule that misses the next one.
func suggestFor(found []string) string {
	seen := map[string]bool{}
	out := make([]string, 0, len(found))
	for _, path := range found {
		suggestion := "--name " + shellQuote(filepath.Base(path))
		if dir := filepath.Base(filepath.Dir(path)); strings.HasPrefix(dir, ".") {
			// A file whose own name is ordinary (config, credentials, hosts.yml) is
			// suggested with the directory that makes it a credential.
			suggestion = "--name " + shellQuote(dir+"/"+filepath.Base(path))
		}
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			suggestion = "--name " + shellQuote(filepath.Base(path)+"/")
		}
		if seen[suggestion] {
			continue
		}
		seen[suggestion] = true
		out = append(out, suggestion)
	}
	return strings.Join(out, " ")
}

// shellQuote wraps a pattern for a command line an operator will paste. Single
// quotes, so a wildcard reaches faramir rather than the shell.
func shellQuote(s string) string {
	if !strings.ContainsAny(s, "*?[ ") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// RefusedBy is what refuses a path, and whether anything does: a rule this
// install renders, whether from its own layout or from an entry the operator
// declared. The same set both entry points are generated from, so an answer
// here is an answer for the file tools and the command guard alike.
func RefusedBy(layout Layout, path string) (string, bool) {
	for _, dir := range installDirs(layout) {
		if dir != "" && (path == dir || strings.HasPrefix(path, dir+"/")) {
			return dir, true
		}
	}
	for _, declared := range perInstallPaths(layout) {
		if path == declared || strings.HasPrefix(path, declared+"/") {
			return declared, true
		}
	}
	for _, rule := range protectedFor(layout) {
		if rule.covers(path) {
			return rule.value, true
		}
	}
	return "", false
}

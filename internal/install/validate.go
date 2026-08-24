package install

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/keeper"
)

// checkReport is the part of `faramir-broker --check` this acts on; the rest is
// passed through as the command's own output.
type checkReport struct {
	Secrets struct {
		Count int `json:"count"`
		// Patterns is the configured globs, Files what they named on disk. Entries
		// naming nothing are a host waiting for its secrets; files that did not
		// load are a fault.
		Patterns []string `json:"patterns"`
		Files    []string `json:"files"`
		Errors   []string `json:"errors"`
		// UnresolvedPatterns is the entries that named nothing, which the broker
		// cannot work out for itself: the secrets directory is the keeper's to
		// list.
		UnresolvedPatterns []string `json:"unresolved_patterns"`
		// NotRedactable is the refs the store read and the redactor refused, by ref
		// and reason. They load and are never injected, so each is a value to
		// lengthen rather than anything about the install.
		NotRedactable map[string]string `json:"not_redactable"`
		// ShadowedRefs is the refs more than one managed file defines with
		// different values, by ref and by which files. The value that lost is on
		// disk and in no redactor, which is what NotRedactable is too, so the two
		// are reported alike.
		ShadowedRefs map[string]string `json:"shadowed_refs"`
		// DegradedLinks is the [[secret.link]] entries that did not load, by ref.
		// Each refuses that ref alone; the broker goes on serving the rest.
		DegradedLinks map[string]string `json:"degraded_links"`
		// Links is how many of Count came from [[secret.link]] entries rather than
		// from a managed file. A count, not the paths, which are the operator's
		// own files. An install whose whole value set is linked keeps no store,
		// and the daemon serves it.
		Links int `json:"links"`
	} `json:"secrets"`
	// Policy is the socket-policy problems, which --check also exits non-zero
	// for. Read here so a caller can tell which reason it is looking at.
	Policy []string `json:"policy"`
}

// The three ref-level states --check exits non-zero for, each of which is a
// value this host manages that no redactor holds. Each has an "only" helper
// because --check exits 1 for several states at once and the exit code cannot
// say which: a caller that has reported one needs to know whether anything else
// is left unaccounted for.
//
// An empty value set is deliberately not among them. It stopped being a
// non-zero exit when the broker started serving one, so counting it here would
// leave a real finding beside it looking unexplained.
func (c checkReport) refStatesOtherThan(mine int) bool {
	others := 0
	for _, n := range []int{len(c.Secrets.NotRedactable), len(c.Secrets.DegradedLinks),
		len(c.Secrets.ShadowedRefs)} {
		others += n
	}
	return others-mine > 0
}

// onlyNotRedactable reports whether a non-zero --check is accounted for by refs
// the redactor refused and nothing else. The distinction earns its place
// because this state is not about the install: the store loaded, the daemons
// are serving, and one value is too short to cover.
func (c checkReport) onlyNotRedactable() bool {
	return len(c.Secrets.NotRedactable) > 0 &&
		len(c.Policy) == 0 &&
		len(c.Secrets.Errors) == 0 &&
		!c.refStatesOtherThan(len(c.Secrets.NotRedactable))
}

// onlyDegradedLinks reports whether a non-zero --check is accounted for by
// links that did not load and nothing else. Like onlyNotRedactable, this is not
// about the install: the store loaded, the daemons are serving every other ref,
// and what is missing is a file another tool owns and this command cannot
// write.
func (c checkReport) onlyDegradedLinks() bool {
	return len(c.Secrets.DegradedLinks) > 0 &&
		len(c.Policy) == 0 &&
		len(c.Secrets.Errors) == 0 &&
		!c.refStatesOtherThan(len(c.Secrets.DegradedLinks))
}

// onlyShadowedRefs is the same question for a ref two managed files defined.
// Not about the install either: every file loaded and the daemons are serving,
// and what is wrong is that one of two values for one name reaches nothing.
func (c checkReport) onlyShadowedRefs() bool {
	return len(c.Secrets.ShadowedRefs) > 0 &&
		len(c.Policy) == 0 &&
		len(c.Secrets.Errors) == 0 &&
		!c.refStatesOtherThan(len(c.Secrets.ShadowedRefs))
}

// refusedRefs is the refused refs and their reasons, ordered, for a message.
func (c checkReport) refusedRefs() string {
	return refsWithReasons(c.Secrets.NotRedactable)
}

// degradedRefs is the same for the links that did not load.
func (c checkReport) degradedRefs() string {
	return refsWithReasons(c.Secrets.DegradedLinks)
}

func refsWithReasons(refs map[string]string) string {
	out := make([]string, 0, len(refs))
	for ref, reason := range refs {
		out = append(out, fmt.Sprintf("%s (%s)", ref, reason))
	}
	slices.Sort(out)
	return strings.Join(out, ", ")
}

// serves reports whether the broker will run exec and redact: something was
// read, and every file it read loaded. Store.Unreadable is the daemon's own
// gate, mirrored here so a probe that runs a brokered command is skipped only
// when it would really be refused.
//
// Links as well as files, because a [[secret.link]] entry fills the value set
// without the keeper contributing anything, and an install whose whole set is
// linked keeps no managed file at all. Counting files alone skipped the probes
// that check redaction on exactly those hosts, and gave the broker refusing as
// the reason when it was serving.
//
// Not a ref count: files that hold nothing still serve, the daemon asking what
// was read rather than what was in it. Configured links rather than resolved
// ones, which the report does not carry: a link whose file has gone reads as
// serving here and the probe then fails on it, which names the fault. The other
// direction skips the probe and reports nothing.
// serves reports whether the broker will run a brokered command at all, which
// is what the probes that send one are gated on. An empty value set is not a
// refusal: it holds no value for output to carry, so the command runs and comes
// back redacted against nothing. What refuses is a managed file that was found
// and did not load.
func (c checkReport) serves() bool {
	return len(c.Secrets.Errors) == 0
}

// stepValidate asks the broker what it can do with what was installed. As the
// broker's own uid, not root: --check opens the SSH keys and the secrets files
// itself, and root reads what the broker cannot.
func (r *runner) stepValidate() error {
	if r.opts.DryRun {
		r.skip("validate", "dry run")
		return nil
	}
	if !systemdRunning() {
		r.skip("validate", "systemd is not running, so nothing is serving")
		return nil
	}
	broker := filepath.Join(r.layout.BinDir, "faramir")
	out, checkErr := r.command("runuser", "-u", r.layout.BrokerUser, "--",
		"env", "FARAMIR_CONFIG="+r.layout.ConfigFile, broker, "broker", "--check")
	// Read before the exit code is judged: what the broker could not load decides
	// whether this is a failure or a host without its secrets yet.
	var report checkReport
	if jsonErr := json.Unmarshal([]byte(out), &report); jsonErr != nil {
		if checkErr != nil {
			return fmt.Errorf("the installed config does not work for %s: %w",
				r.layout.BrokerUser, checkErr)
		}
		return fmt.Errorf("could not read the --check report: %w", jsonErr)
	}
	if checkErr != nil {
		// A configured file not yet created is what every first install looks like.
		// The running broker still refuses to serve, but failing the install over it
		// leaves no way to reach a working host. Anything else, including a file
		// that is there and did not load, is fatal.
		if absent := report.Secrets.UnresolvedPatterns; len(absent) == len(report.Secrets.Patterns) &&
			len(absent) > 0 {
			// What it does is refuse, not run bare. Said that way round: a warning
			// that reads as an exposure teaches the wrong reflex for the day a value
			// set really does fail to load.
			r.warnf("the broker is configured for %s, which %s named no file yet, so it is serving "+
				"nothing and refuses every brokered command. Write the secrets directory with "+
				"sops and re-run",
				strings.Join(absent, ", "),
				map[bool]string{true: "has", false: "have"}[len(absent) == 1])
			r.step("validate", false, "no secrets yet")
			return nil
		}
		// Links that did not load. Fatal: the ref answers nothing, and an install
		// that finished over it would leave `status` and `doctor` failing on a host
		// this command called done. The file belongs to another tool, so the
		// remedies are the operator's and are named rather than attempted.
		if report.onlyDegradedLinks() {
			return fmt.Errorf("%s did not load, so those refs answer nothing: %s\nRestore what each names, fix "+
				"its selector, or take the entry out with `sudo faramir link rm REF`, then run "+
				"this again",
				linkEntries(len(report.Secrets.DegradedLinks)), report.degradedRefs())
		}
		// Refs the redactor refused. Reported and carried on from, where a link
		// that did not load above is fatal, and the difference is what each costs
		// to leave standing.
		//
		// This command rewrites config.toml before it validates, and [secret]
		// min_length is one of the settings it writes. Failing here would make the
		// bound impossible to raise: `--secret-min-length 12` on a host holding a
		// shorter value would record the new bound and then fail over the values it
		// just refused, leaving a run that wrote the config and reported failure.
		// An install cannot lengthen a secret either. `faramir doctor` fails on
		// this and `faramir status` exits non-zero over it, so a host in this state
		// is not one anything calls healthy.
		if report.onlyNotRedactable() {
			r.warnf("%d ref(s) cannot be redacted, so they are never injected: %s. Fix each with "+
				"`sudo faramir vault edit`; the reason beside it says how",
				len(report.Secrets.NotRedactable), report.refusedRefs())
			r.step("validate", false, "installed; refs to fix")
			return nil
		}
		return fmt.Errorf("the installed config does not work for %s: %w\nA [secret] file named there is one "+
			"the broker could not load. A ref under not_redactable needs fixing instead, and a "+
			"[[secret.link]] entry there claims a ref the managed store defines: remove it "+
			"with `sudo faramir link rm REF`",
			r.layout.BrokerUser, checkErr)
	}

	// A value absent from the set is neither injectable nor redacted, so zero refs
	// from a secrets directory that exists is a broker protecting nothing while
	// looking healthy. Guarded on the resolved files rather than the patterns, no
	// files at all being what a first install looks like.
	if len(report.Secrets.Files) > 0 && report.Secrets.Count == 0 {
		r.warnf("the broker read %s and loaded no refs, so nothing is injectable "+
			"and nothing is redacted: a command that prints a credential prints it "+
			"in plaintext. %s",
			strings.Join(report.Secrets.Files, ", "), loadErrorDetail(report.Secrets.Errors))
	}

	// Ansible loads every .yml under group_vars/ and host_vars/ as a vars file,
	// and a sops file is valid YAML: each var binds to its ENC[...] ciphertext,
	// and a name sorting after vars.yml overwrites the environment lookup the
	// injection relies on. Nothing errors.
	for _, file := range report.Secrets.Files {
		if strings.Contains(file, "/group_vars/") || strings.Contains(file, "/host_vars/") {
			return fmt.Errorf("%s is under group_vars/ or host_vars/, which Ansible "+
				"auto-loads. Every var would resolve to its ENC[...] ciphertext "+
				"instead of the injected value, silently. Move it to %s",
				file, r.layout.SecretsDir())
		}
	}

	r.brokerChecked = true
	r.brokerLoadedRefs = report.Secrets.Count
	r.step("validate", false, fmt.Sprintf("%d ref(s) from %d file(s)",
		report.Secrets.Count, len(report.Secrets.Files)))

	// Asked through the broker rather than read off disk, what matters being what
	// a brokered command gets. The daemon comes up without a loaded key and lets
	// SSH fail where it is used, so nothing else would say the key is missing at
	// install time. Gated on the key that reached disk rather than on --ssh-key,
	// which is a relocation and empty on most runs.
	//
	// Skipped while the broker is refusing, which a managed file that did not
	// load is: this probe would report that refusal as an SSH fault.
	if r.sshKey != "" && !report.serves() {
		r.warnf("a managed file did not load, so the broker refuses brokered " +
			"commands and what its ssh-agent holds could not be asked. Fix what the " +
			"store reported, then: faramir doctor")
		r.step("broker ssh agent", false, "not asked")
	}
	if r.sshKey != "" && report.serves() {
		out, agentErr := r.command(filepath.Join(r.layout.BinDir, "faramir"),
			"run", "--quiet", "--", "ssh-add", "-l")
		// The error carries stderr, where the reason is; dropping it reports every
		// failure as "holds no usable key ()".
		if agentErr != nil {
			if why := NestedRun(); why != "" {
				return fmt.Errorf("could not ask the broker what its agent holds: %s",
					why)
			}
			return fmt.Errorf("could not ask the broker what its agent holds: %w\n"+
				"A brokered command runs where its caller was, so this also fails "+
				"when init is run from a directory %s cannot enter",
				agentErr, r.layout.BrokerUser)
		}
		if !strings.Contains(out, "SHA256") {
			return fmt.Errorf("the broker's ssh-agent holds no usable key (%s), though [ssh] key names %s: "+
				"brokered commands reach no managed host. Check %s can read it and it is not "+
				"passphrase-protected, then restart faramir-broker",
				strings.TrimSpace(out), r.sshKey, r.layout.BrokerUser)
		}
		r.step("broker ssh agent", false, "holds a usable key")
	}

	return nil
}

func loadErrorDetail(errors []string) string {
	if len(errors) == 0 {
		return "The broker reported no load error, so the file parsed and is empty " +
			"rather than unreadable."
	}
	return "Load errors: " + strings.Join(errors, "; ")
}

// storeHolds is what the value set is made of beside an entry that named no
// file, which is what separates a host keeping its secrets in links alone, or
// in the files another entry did name, from one whose store went missing.
//
// Serving nothing is the last case and not the default: the daemon refuses exec
// and redact on a store where no managed file loaded and nothing is linked, so
// one entry naming nothing while another resolved is a value set that is served
// and must not be described as one that is not.
func (c checkReport) storeHolds() string {
	switch {
	case c.Secrets.Links > 0 && c.Secrets.Count > c.Secrets.Links:
		return fmt.Sprintf("%d ref(s) are served, %d of them from %s",
			c.Secrets.Count, c.Secrets.Links, linkEntries(c.Secrets.Links))
	case c.Secrets.Links > 0:
		return "the whole value set is " + linkEntries(c.Secrets.Links)
	// A file that loaded and held nothing still opens the gate, which is on a
	// managed file having been read and not on how many refs came out of it, so
	// this is neither a store that serves values nor one that refuses the ops.
	case len(c.Secrets.Files) > 0 && c.Secrets.Count == 0:
		return fmt.Sprintf("%d file(s) loaded and held no ref, so nothing is "+
			"injected and nothing is redacted", len(c.Secrets.Files))
	case len(c.Secrets.Files) > 0:
		return fmt.Sprintf("%d ref(s) are served from %d file(s)",
			c.Secrets.Count, len(c.Secrets.Files))
	}
	return "nothing is injected and nothing is redacted"
}

// linkNote names the linked share of a value set that also has managed files,
// so a count that changed says which half it changed in.
func (c checkReport) linkNote() string {
	if c.Secrets.Links == 0 {
		return ""
	}
	return " and " + linkEntries(c.Secrets.Links)
}

// storeFinding is what the `secrets store` check reports: what the store holds,
// and whether anything about it is wrong.
//
// An empty value set is a warning rather than a failure, in every shape it
// comes in. A host that manages no credentials is a host with nothing to leak,
// and a host that has not written its first secret is every install on its
// first day. What still fails is a managed file that was found and did not
// load: there the broker knows values exist that it cannot cover, and it
// refuses the ops rather than running them.
//
// The warning matters because a store on a filesystem that is not mounted is
// the one case that looks like an empty install and is not. Nothing can tell
// those apart, so both are reported and neither stops the host.
func storeFinding(c checkReport) (Status, string) {
	switch {
	case len(c.Secrets.Errors) > 0:
		// First, and on its own: the daemon refuses every redacted op while one
		// file did not load, whatever else did, so a ref count beside it would
		// describe a store that is not being served.
		return StatusFailed, loadErrorDetail(c.Secrets.Errors)
	case len(c.Secrets.Patterns) == 0 && c.Secrets.Links == 0:
		return StatusWarn, "no managed sops files and no [[secret.link]] entries are configured, so commands " +
			"run with nothing injected and nothing redacted"
	case len(c.Secrets.UnresolvedPatterns) > 0:
		// A warning rather than a failure, because this cannot tell a host that
		// keeps no store from one whose store went missing: the pattern is derived
		// from the config directory, so it is on every install and names nothing
		// until a first file is written. What is served is reported beside it,
		// that being what tells an operator which of the two they are looking at.
		detail := fmt.Sprintf("%s, so %s",
			strings.Join(c.Secrets.UnresolvedPatterns, "; "), c.storeHolds())
		// An entry that could not be searched at all is the exception to the
		// paragraph above: no host waiting for its first secret looks like a
		// directory this account may not read, so there is nothing here to
		// confuse it with. Every managed value is out of the redactor until it
		// is fixed, which is what a file that did not load is failed for.
		if slices.ContainsFunc(c.Secrets.UnresolvedPatterns, keeper.UnresolvedWasRefused) {
			return StatusFailed, detail
		}
		// The guess is only for entries that gave no reason of their own. One
		// that names a directory it could not read has already said why, and
		// being told to go and write a file sends the operator past it.
		if everyEntryOnlyMissedAMatch(c.Secrets.UnresolvedPatterns) {
			detail += ". Either the secrets have not been written yet, or they " +
				"are on a filesystem that is not mounted"
		}
		return StatusWarn, detail
	case c.Secrets.Count == 0 && len(c.Secrets.Files) == 0:
		// Reachable on an install whose secrets are all linked and whose links have
		// all gone: nothing was read, so there is no file to name.
		return StatusWarn, fmt.Sprintf("no managed file was read and %s produced "+
			"no value, so nothing is injectable and nothing is redacted",
			linkEntries(c.Secrets.Links))
	case c.Secrets.Count == 0:
		return StatusWarn, fmt.Sprintf("read %s and loaded no refs, so nothing is "+
			"injectable and nothing is redacted",
			strings.Join(c.Secrets.Files, ", "))
	}
	return StatusOK, fmt.Sprintf("%d ref(s) from %d file(s)%s",
		c.Secrets.Count, len(c.Secrets.Files), c.linkNote())
}

// everyEntryOnlyMissedAMatch reports whether nothing stopped the search: each
// entry looked where it was told and found no file there.
func everyEntryOnlyMissedAMatch(entries []string) bool {
	for _, entry := range entries {
		if !strings.HasSuffix(entry, keeper.NoMatchReason) {
			return false
		}
	}
	return true
}

// linkEntries names a count of link entries, singular where there is one: this
// reads in the middle of a sentence an operator is being told something by.
func linkEntries(n int) string {
	if n == 1 {
		return "1 [[secret.link]] entry"
	}
	return fmt.Sprintf("%d [[secret.link]] entries", n)
}

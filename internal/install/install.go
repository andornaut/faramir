package install

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/version"
)

// Options is one `faramir init` invocation.  Everything an operator can decide;
// the paths that follow from those decisions are in Layout.
type Options struct {
	// Operator is the account the coding agent runs as.  There is no account of
	// its own: the work it is asked to do is the operator's, and a separate uid
	// could reach none of it.  What the three service accounts below hold is
	// what the operator cannot read either.
	Operator string

	Group      string
	StoreGroup string
	BrokerUser string
	KeeperUser string
	ExecUser   string

	// ConfigDir holds config.toml, config.d/, the age key and the store.  One
	// path rather than several: the key follows the config so that a store in an
	// encrypted home has the key that opens it in there too, and a store moved
	// away on its own would leave that key behind.
	ConfigDir string

	// AgeRecipients are listed in .sops.yaml alongside the keeper's, so an
	// account that is not the keeper can still read the files it is responsible
	// for.  Without one, editing a value or rotating a credential has to go
	// through the broker.
	//
	// Public keys only.  No identity is minted for anybody but the keeper: a
	// second private key is a second way into the store, and it earns that only
	// where the ciphertext is backed up somewhere the keeper's key is not.
	AgeRecipients []string

	// SSHKey is the identity the broker lends to brokered commands through an
	// agent it owns, generated when missing.  A key of the broker's own rather
	// than the operator's: the executor's uid can authenticate with it without
	// being able to read it.  Empty leaves [ssh] keys unset, which works but
	// puts the keys somewhere the executor can read.
	SSHKey string

	// No tree is enrolled here.  A tree is per project and there is no limit to
	// how many there are, where this runs once per machine; and the working
	// directory is the obvious default for "enrol this project" and a hazard for
	// "provision this host", which would enrol whatever directory it was run
	// from.  See `faramir init-project`.

	// Agents names the coding agents whose own settings get the Read deny
	// rules, which refuse to open key material wherever the agent is working
	// and take nothing away.  Naming one is what asks for them: empty writes
	// nothing, so there is no state where a name is given and ignored.
	//
	// The PreToolUse hook is not installed here: it is per project, because
	// registering it auto-approves Bash for that project.
	//
	// The same names `faramir init-project --agent` takes, which defaults to
	// Claude Code where this does not: enrolling a tree is the point of that
	// command and an aside to this one.
	Agents []string

	// DryRun computes every answer and writes nothing.  Steps that cannot be
	// evaluated without accounts that do not exist yet are reported as skipped
	// rather than guessed at.
	DryRun bool

	// Log receives one line per step for a human watching.  The machine-readable
	// answer is the returned Report.
	Log func(string)
}

// Step is one unit of work and whether it changed anything.  A caller driving
// this from a configuration manager reads Changed rather than stat-ing the host
// before and after.
type Step struct {
	Name    string `json:"step"`
	Changed bool   `json:"changed"`
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Report is the whole run.
type Report struct {
	Version string `json:"version"`
	Changed bool   `json:"changed"`
	DryRun  bool   `json:"dry_run,omitempty"`
	Steps   []Step `json:"steps"`
	// Warnings are the things that install cleanly and then do not work.  They
	// are not failures, because each has a legitimate shape, but every one of
	// them has left somebody with a broker that looked healthy and did nothing.
	Warnings []string `json:"warnings,omitempty"`
	// BrokerPublicKey has to be in authorized_keys on every managed host or
	// brokered commands authenticate as nobody.  Reported every run, not only
	// when the key was just generated.
	BrokerPublicKey string `json:"broker_public_key,omitempty"`
	// AgeRecipients is who can decrypt the managed files: what .sops.yaml lists,
	// read back from the file, and not what --age-recipient asked for.  The two
	// agree only on the run that creates it, and reporting the request was how a
	// flag that had been ignored for months still read as applied.  Empty when
	// the file could not be read or was not reached, rather than guessed at.
	AgeRecipients []string `json:"age_recipients,omitempty"`
}

type runner struct {
	opts   Options
	layout Layout
	fs     fsys
	report Report

	// The directory the running faramir came out of, which is where the binary
	// installed onto the host is copied from: `sudo ./bin/faramir init` finds
	// its siblings, an installed one reinstalls itself, and a release unpacked
	// into a staging directory installs from there.  Nothing names it, so the
	// binary that provisions the host is always the one that lands on it.
	binaries string

	// What the validation step actually established, as against what it was
	// asked to check.  It skips entirely under DryRun and on a host with no
	// systemd, so the irreversible step below cannot read its own absence as
	// approval.
	brokerLoadedRefs int
	brokerChecked    bool

	// The keeper's own age recipient, empty when it could not be read: the
	// plaintext key has been removed and the sealed credential is not something
	// this decrypts.  A .sops.yaml written without it encrypts every later value
	// to everyone except the one account that has to decrypt them.
	keeperRecipient string

	// What has changed that the running daemons would not otherwise pick up.
	// Neither re-reads its config while running and none of them reloads its own
	// binary, so those are the changes a restart is for; nothing else is worth
	// killing the brokered commands in flight over.
	needsRestart   bool
	restartReasons []string

	// Resolved after the accounts step.  keep when the account does not exist,
	// which only happens under DryRun.
	operatorUID  int
	operatorHome string
	brokerUID    int
	keeperUID    int
	execUID      int
	groupGID     int
	storeGID     int
	brokerGID    int
	keeperGID    int
	execGID      int
}

// Run provisions the host.  Idempotent: a second run with the same options
// changes nothing and reports so.
func Run(opts Options) (Report, error) {
	opts.applyDefaults()
	layout, err := opts.layout()
	if err != nil {
		return Report{}, err
	}
	run := &runner{
		opts:   opts,
		layout: layout,
		fs:     fsys{dryRun: opts.DryRun},
		report: Report{Version: version.Version, DryRun: opts.DryRun},
	}
	if self, err := os.Executable(); err == nil {
		run.binaries = filepath.Dir(self)
	}
	if err := run.preflight(); err != nil {
		return run.report, err
	}
	steps := []func() error{
		run.stepAccounts,
		run.resolveIDs,
		run.stepDirectories,
		run.stepAgeKey,
		run.stepSopsConfig,
		run.stepSSHKey,
		run.stepBinaries,
		run.stepConfig,
		// Before the units are written and anything is started: it grants the
		// traversal that lets a service uid reach a config or a store under the
		// operator's home, and a daemon started without it exits before it opens
		// a socket.
		run.stepReachable,
		run.stepUnits,
		run.stepSystemd,
		run.stepAgentConfig,
		run.stepValidate,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return run.report, err
		}
	}
	// AgeRecipients is set by the sops config step, which is the only thing here
	// that has read the file.  Not restated from the options: that is the request,
	// and on every run after the first the request is not what governs.
	return run.report, nil
}

func (o *Options) applyDefaults() {
	if o.Group == "" {
		o.Group = DefaultGroup
	}
	if o.BrokerUser == "" {
		o.BrokerUser = DefaultBrokerUser
	}
	if o.KeeperUser == "" {
		o.KeeperUser = DefaultKeeperUser
	}
	// After KeeperUser, whose primary group this is.  The keeper is the only
	// account that opens a managed file, so the group that owns the store is
	// the one the account already has, and there is no membership to keep
	// accurate.
	if o.StoreGroup == "" {
		o.StoreGroup = o.KeeperUser
	}
	if o.ExecUser == "" {
		o.ExecUser = DefaultExecUser
	}
	if o.ConfigDir == "" {
		o.ConfigDir = DefaultConfigDir
	}
}

// layout derives the paths from the options and checks them.
func (o Options) layout() (Layout, error) {
	layout := Layout{
		Group:      o.Group,
		StoreGroup: o.StoreGroup,
		BrokerUser: o.BrokerUser,
		KeeperUser: o.KeeperUser,
		ExecUser:   o.ExecUser,
		ConfigDir:  filepath.Clean(o.ConfigDir),
		BinDir:     DefaultBinDir,
		LibexecDir: DefaultLibexecDir,
		DocDir:     DefaultDocDir,
		RunDir:     DefaultRunDir,
		LogDir:     DefaultLogDir,
		SSHKey:     o.SSHKey,
	}
	layout.ConfigFile = filepath.Join(layout.ConfigDir, "config.toml")
	// Beside the config, including when that is inside the operator's own home.
	// What keeps the operator out of the key is its 0400 keeper ownership, which
	// holds wherever it sits: owning the directory is permission to unlink the
	// file, not to read it.  Replacing it is a deliberate act, and a store
	// encrypted to the key it replaced then decrypts for nobody, so what that
	// buys an attacker is denial of service rather than disclosure.
	//
	// Following the config is what puts the key inside an encrypted home when
	// the store is already there, so a powered-off disk carries neither.
	layout.AgeKeyPath = filepath.Join(layout.ConfigDir, "age.key")
	return layout, layout.validate()
}

// preflight refuses the run before anything is written.  Each of these
// otherwise surfaces once the binaries are already on the host, leaving an
// install half applied.
func (r *runner) preflight() error {
	if os.Geteuid() != 0 && !r.opts.DryRun {
		return errors.New("faramir init must run as root: it creates accounts, " +
			"writes under /etc and installs systemd units")
	}
	if r.opts.Operator == "" || r.opts.Operator == "root" {
		return errors.New("name the account the coding agent runs as: pass --operator, " +
			"or run through sudo so SUDO_USER carries it. It must not be root: " +
			"the operator owns the checkouts a brokered command runs in")
	}
	if !userExists(r.opts.Operator) {
		return fmt.Errorf("no such user: %s", r.opts.Operator)
	}
	// Before any account exists and long before .sops.yaml is written, because
	// that file is written once and then kept: a recipient that is not one lands
	// in a world-readable rule and stays there, and what it breaks -- every later
	// encrypt, or the privacy of a private key -- surfaces nowhere near the run
	// that accepted it.  The keeper's own is added after this and needs no check,
	// having just been read out of the key.
	for _, recipient := range r.opts.AgeRecipients {
		if err := agekey.ValidateRecipient(recipient); err != nil {
			return fmt.Errorf("--age-recipient: %w", err)
		}
	}
	// An encrypted home is a different directory before its owner logs in, and
	// writing to it then lands in the unencrypted backing store, where it is
	// shadowed the moment the home mounts.  The install would look like it
	// worked and the daemons would never see the file again.  The config
	// directory answers for the store and the key as well, both being under it.
	if home := homeOf(r.layout.ConfigDir); home != "" && looksEncrypted(home) && !homeIsMounted(home) {
		return fmt.Errorf("%s is an encrypted home and is not mounted, and %s is "+
			"inside it. Installing now would write plaintext to the backing store, "+
			"where it is hidden once the home mounts. Log in as its owner first",
			home, r.layout.ConfigDir)
	}
	// The binaries are built ahead of time, so this needs no toolchain on the
	// target host.  Checked here rather than at the install step, which is
	// after the accounts and the age key have already been created.
	if r.binaries == "" {
		return errors.New("cannot find the directory this faramir was run from")
	}
	var missing []string
	for _, name := range installedBinaries {
		if !exists(filepath.Join(r.binaries, name)) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("not built in %s: %s. Run 'make build', then run the "+
			"faramir it built", r.binaries, strings.Join(missing, ", "))
	}
	return nil
}

// step records one unit of work and its outcome.
func (r *runner) step(name string, changed bool, detail string) {
	r.report.Steps = append(r.report.Steps, Step{Name: name, Changed: changed, Detail: detail})
	if changed {
		r.report.Changed = true
	}
	if r.opts.Log == nil {
		return
	}
	mark := "ok"
	if changed {
		mark = "changed"
	}
	line := fmt.Sprintf("%-9s %s", mark, name)
	if detail != "" {
		line += ": " + detail
	}
	r.opts.Log(line)
}

// skip records a step that could not be evaluated.  Only reachable under
// DryRun, where the accounts a step reads may not exist yet.
func (r *runner) skip(name, why string) {
	r.report.Steps = append(r.report.Steps, Step{Name: name, Skipped: true, Detail: why})
	if r.opts.Log != nil {
		r.opts.Log(fmt.Sprintf("%-9s %s: %s", "skipped", name, why))
	}
}

// reportPresence is the dry-run answer for a step whose only question is
// whether a file is already there.  Nothing is opened: several of these are key
// material, and a report is not a reason to read one.
func (r *runner) reportPresence(name, path, wouldCreate string) {
	present, known := probe(path)
	switch {
	case !known:
		r.skip(name, "cannot tell whether "+path+" is there without root")
	case present:
		r.step(name, false, "keeping "+path)
	default:
		r.step(name, true, wouldCreate+" "+path)
	}
}

// restartFor records that a running daemon is now behind what is installed.
func (r *runner) restartFor(what string) {
	r.needsRestart = true
	if !slices.Contains(r.restartReasons, what) {
		r.restartReasons = append(r.restartReasons, what)
	}
}

func (r *runner) warn(format string, args ...any) {
	r.report.Warnings = append(r.report.Warnings, fmt.Sprintf(format, args...))
}

// command runs a program and returns its standard output.
//
// stdout alone, never combined: the broker prints its --check report on stdout
// and logs on stderr, and it logs on every load whether or not anything went
// wrong.  A combined capture puts a log line in front of the JSON and makes
// every report unparseable, which reads as a broken install on a working host.
// stderr is carried in the error instead, which is where it is wanted.
//
// Nothing here handles a secret: the age key is minted in process and never
// passed on a command line, and sops is run by the keeper, not by this.
func (r *runner) command(name string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// commandCombined is command for the programs whose answer is on stderr.
// systemd-analyze verify reports what systemd will silently ignore there and
// exits 0 either way, so the output is the only thing worth reading.
func (r *runner) commandCombined(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

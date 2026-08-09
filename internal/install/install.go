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

// Options is one `faramir init` invocation: everything an operator can decide.
// The paths that follow are in Layout.
type Options struct {
	// Operator is the account the coding agent runs as.  It has no account of
	// its own: the work it does is the operator's, and a separate uid could
	// reach none of it.
	Operator string

	Group      string
	StoreGroup string
	BrokerUser string
	KeeperUser string
	ExecUser   string

	// ConfigDir holds config.toml, config.d/, the age key and the store.  One
	// path, so a store in an encrypted home has the key that opens it there
	// too.
	ConfigDir string

	// AgeRecipients are listed in .sops.yaml alongside the keeper's, so an
	// account that is not the keeper can read the files it is responsible for.
	// Public keys only: a second private key is a second way into the store.
	AgeRecipients []string

	// SSHKey is the identity the broker lends through an agent it owns,
	// generated when missing, so the executor can authenticate with it without
	// reading it.  Empty leaves [ssh] keys unset, which puts the keys somewhere
	// the executor can read.
	SSHKey string

	// No tree is enrolled here: a tree is per project and this runs once per
	// machine.  See `faramir init-project`.

	// Agents names the coding agents whose settings get the Read deny rules,
	// which refuse to open key material wherever the agent is working.  Empty
	// writes nothing.
	//
	// The PreToolUse hook is per project, because registering it auto-approves
	// Bash there.  The same names `faramir init-project --agent` takes, which
	// unlike this defaults to Claude Code.
	Agents []string

	// DryRun computes every answer and writes nothing.  A step needing accounts
	// that do not exist yet is reported as skipped.
	DryRun bool

	// Log receives one line per step; the machine-readable answer is Report.
	Log func(string)
}

// Step is one unit of work and whether it changed anything, so a configuration
// manager reads Changed rather than stat-ing the host.
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
	// Warnings are the things that install cleanly and then do not work.  Not
	// failures, each having a legitimate shape.
	Warnings []string `json:"warnings,omitempty"`
	// BrokerPublicKey has to be in authorized_keys on every managed host.
	// Reported every run, not only when it was generated.
	BrokerPublicKey string `json:"broker_public_key,omitempty"`
	// AgeRecipients is who can decrypt the managed files, read back from
	// .sops.yaml rather than taken from --age-recipient: the two agree only on
	// the run that creates it.  Empty when the file could not be read.
	AgeRecipients []string `json:"age_recipients,omitempty"`
}

type runner struct {
	opts   Options
	layout Layout
	fs     fsys
	report Report

	// The directory the running faramir came out of, so the binary that
	// provisions the host is the one that lands on it.  Nothing names it.
	binaries string

	// What the validation step established, not what it was asked to check: it
	// skips under DryRun and without systemd, so the irreversible step below
	// cannot read its absence as approval.
	brokerLoadedRefs int
	brokerChecked    bool

	// The keeper's own age recipient, empty when it could not be read.  A
	// .sops.yaml written without it encrypts every later value to everyone
	// except the account that has to decrypt them.
	keeperRecipient string

	// What the running daemons would not otherwise pick up.  None re-reads its
	// config or reloads its binary, and nothing else is worth killing the
	// commands in flight for.
	needsRestart   bool
	restartReasons []string

	// Resolved after the accounts step; keep when the account does not exist,
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
		// Before the units are written: it grants the traversal that lets a
		// service uid reach a config under the operator's home.
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
	// Set by the sops config step, the only thing here that read the file, not
	// restated from the options, which are only the request.
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
	// After KeeperUser, whose primary group this is: the keeper is the only
	// account that opens a managed file, so there is no membership to keep.
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
	// Beside the config, even inside the operator's home: what keeps the
	// operator out is the key's 0400 keeper ownership, and owning the directory
	// is permission to unlink the file, not to read it.  Following the config
	// puts the key inside an encrypted home when the store is already there.
	layout.AgeKeyPath = filepath.Join(layout.ConfigDir, "age.key")
	return layout, layout.validate()
}

// preflight refuses the run before anything is written, each of these otherwise
// surfacing with the install half applied.
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
	// Before .sops.yaml is written, that file being written once and then kept:
	// a bad recipient lands in a world-readable rule and breaks every later
	// encrypt, nowhere near the run that accepted it.  The keeper's own is read
	// out of the key and needs no check.
	for _, recipient := range r.opts.AgeRecipients {
		if err := agekey.ValidateRecipient(recipient); err != nil {
			return fmt.Errorf("--age-recipient: %w", err)
		}
	}
	// An encrypted home is a different directory before its owner logs in, so a
	// write lands in the backing store and is shadowed the moment it mounts.
	// The config directory answers for the store and the key too.
	if home := homeOf(r.layout.ConfigDir); home != "" && looksEncrypted(home) && !homeIsMounted(home) {
		return fmt.Errorf("%s is an encrypted home and is not mounted, and %s is "+
			"inside it. Installing now would write plaintext to the backing store, "+
			"where it is hidden once the home mounts. Log in as its owner first",
			home, r.layout.ConfigDir)
	}
	// The config directory is the one faramir creates whose parent can belong to
	// the operator.  ensureDir chowns every ancestor it has to create, so an
	// absent parent comes back root-owned and is no longer its owner's to write:
	// ~/.config created that way breaks every other tool that keeps state there.
	// The directories under /usr/local are faramir's own and are created as
	// usual.
	if parent := filepath.Dir(r.layout.ConfigDir); !exists(parent) {
		return fmt.Errorf("%s does not exist, and %s is inside it. Create it with "+
			"the ownership you want first: creating it here would hand it to root",
			parent, r.layout.ConfigDir)
	}
	// The binaries are built ahead of time.  Checked here rather than at the
	// install step, which is after the accounts and the age key exist.
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

// skip records a step that could not be evaluated.  Only under DryRun.
func (r *runner) skip(name, why string) {
	r.report.Steps = append(r.report.Steps, Step{Name: name, Skipped: true, Detail: why})
	if r.opts.Log != nil {
		r.opts.Log(fmt.Sprintf("%-9s %s: %s", "skipped", name, why))
	}
}

// reportPresence is the dry-run answer for a step that only asks whether a file
// is there.  Nothing is opened: several are key material.
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

// command runs a program and returns its standard output.  stdout alone: the
// broker prints its --check report there and logs on stderr on every load, so a
// combined capture would make every report unparseable.  stderr is carried in
// the error.
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
// systemd-analyze verify reports there and exits 0 either way.
func (r *runner) commandCombined(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

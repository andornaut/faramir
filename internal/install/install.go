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
	BrokerUser string
	KeeperUser string
	ExecUser   string

	ConfigDir  string
	SecretsDir string

	// Binaries is the directory the built binaries are read from.  Defaults to
	// the directory holding the running faramir, so `sudo ./bin/faramir init`
	// finds its siblings and an installed one reinstalls itself.
	Binaries string

	// AgeRecipients are listed in .sops.yaml alongside the keeper's, so an
	// account that is not the keeper can still read the files it is responsible
	// for.  Without one, editing a value or rotating a credential has to go
	// through the broker.
	AgeRecipients []string

	// OperatorAgeKey is minted if absent and added to AgeRecipients.  It is the
	// ordinary way to get the entry above, and it is not a boundary: the coding
	// agent runs as this account, so it can read this identity and decrypt the
	// store directly.  The broker keeps values out of the agent's context and
	// redacts what comes back; it does not stop an agent that goes looking.
	OperatorAgeKey string

	// SSHKey is the identity the broker lends to brokered commands through an
	// agent it owns, generated when missing.  A key of the broker's own rather
	// than the operator's: the executor's uid can authenticate with it without
	// being able to read it.  Empty leaves [ssh] keys unset, which works but
	// puts the keys somewhere the executor can read.
	SSHKey string

	// SealAgeKey binds the age key to this host's TPM and has the keeper take
	// it from an encrypted credential.  What it buys is protection at rest:
	// 0400 keeper is a running-system boundary, and powered off the key is an
	// ordinary file that decrypts every managed secret retroactively.
	SealAgeKey bool

	// RemovePlaintextAgeKey deletes the plaintext once the keeper is proven to
	// run from the sealed credential.  Separate from SealAgeKey because it is
	// irreversible in the way that matters: sealing binds to PCR 7, so changing
	// Secure Boot policy or clearing the TPM stops the blob decrypting and the
	// only way back is sealing the original key again.
	RemovePlaintextAgeKey bool

	// No tree is enrolled here.  A tree is per project and there is no limit to
	// how many there are, where this runs once per machine; and the working
	// directory is the obvious default for "enrol this project" and a hazard for
	// "provision this host", which would enrol whatever directory it was run
	// from.  See `faramir init-project`.

	// AgentConfig installs the Read deny rules into the operator's own Claude
	// settings.  They refuse to open key material wherever the agent is working
	// and take nothing away.  The PreToolUse hook is not installed here: it is
	// per project, because registering it auto-approves Bash for that project.
	AgentConfig bool

	// OverwriteConfig replaces an installed config.toml instead of keeping it
	// and writing config.toml.dist beside it.  Destructive: edits made on the
	// host are lost.
	OverwriteConfig bool

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
	// AgeRecipients is who can decrypt the managed files.
	AgeRecipients []string `json:"age_recipients,omitempty"`
}

type runner struct {
	opts   Options
	layout Layout
	fs     fsys
	report Report

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
	if err := run.preflight(); err != nil {
		return run.report, err
	}
	steps := []func() error{
		run.stepAccounts,
		run.resolveIDs,
		run.stepDirectories,
		run.stepAgeKey,
		run.stepOperatorAgeKey,
		run.stepSopsConfig,
		run.stepSSHKey,
		run.stepBinaries,
		run.stepConfig,
		run.stepInitDropIn,
		run.stepSealAgeKey,
		// Before the units are written and anything is started: it grants the
		// traversal that lets a service uid reach a config or a store under the
		// operator's home, and a daemon started without it exits before it opens
		// a socket.
		run.stepReachable,
		run.stepUnits,
		run.stepSystemd,
		run.stepAgentConfig,
		run.stepValidate,
		run.stepRemovePlaintextAgeKey,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return run.report, err
		}
	}
	run.report.AgeRecipients = run.opts.AgeRecipients
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
	if o.ExecUser == "" {
		o.ExecUser = DefaultExecUser
	}
	if o.ConfigDir == "" {
		o.ConfigDir = DefaultConfigDir
	}
	if o.SecretsDir == "" {
		o.SecretsDir = filepath.Join(o.ConfigDir, "secrets")
	}
	if o.Binaries == "" {
		if self, err := os.Executable(); err == nil {
			o.Binaries = filepath.Dir(self)
		}
	}
}

// layout derives the paths from the options and checks them.
func (o Options) layout() (Layout, error) {
	layout := Layout{
		Group:      o.Group,
		BrokerUser: o.BrokerUser,
		KeeperUser: o.KeeperUser,
		ExecUser:   o.ExecUser,
		ConfigDir:  filepath.Clean(o.ConfigDir),
		SecretsDir: filepath.Clean(o.SecretsDir),
		BinDir:     DefaultBinDir,
		LibexecDir: DefaultLibexecDir,
		DocDir:     DefaultDocDir,
		RunDir:     DefaultRunDir,
		LogDir:     DefaultLogDir,
		SealAgeKey: o.SealAgeKey,
	}
	layout.ConfigFile = filepath.Join(layout.ConfigDir, "config.toml")
	// Not under ConfigDir: that may be inside the operator's own home, and the
	// age key is the one file this project exists to keep them out of.  The
	// directory is 0755 root:root and the key's own 0400 is what protects it.
	layout.AgeKeyPath = filepath.Join(DefaultConfigDir, "age.key")
	layout.AgeKeyCred = layout.AgeKeyPath + ".cred"
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
			"set OPERATOR, or run through sudo so SUDO_USER carries it. It must not " +
			"be root: the operator owns the checkouts a brokered command runs in")
	}
	if !userExists(r.opts.Operator) {
		return fmt.Errorf("no such user: %s", r.opts.Operator)
	}
	// An encrypted home is a different directory before its owner logs in, and
	// writing to it then lands in the unencrypted backing store, where it is
	// shadowed the moment the home mounts.  The install would look like it
	// worked and the daemons would never see the file again.
	for _, dir := range []string{r.layout.ConfigDir, r.layout.SecretsDir} {
		home := homeOf(dir)
		if home == "" || !looksEncrypted(home) || homeIsMounted(home) {
			continue
		}
		return fmt.Errorf("%s is an encrypted home and is not mounted, and %s is "+
			"inside it. Installing now would write plaintext to the backing store, "+
			"where it is hidden once the home mounts. Log in as its owner first",
			home, dir)
	}
	// The binaries are built ahead of time, so this needs no toolchain on the
	// target host.  Checked here rather than at the install step, which is
	// after the accounts and the age key have already been created.
	if r.opts.Binaries == "" {
		return errors.New("cannot find the built binaries: pass --binaries DIR")
	}
	var missing []string
	for _, name := range requiredBinaries {
		if !exists(filepath.Join(r.opts.Binaries, name)) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("not built in %s: %s. Run 'make build', or pass --binaries "+
			"DIR naming a directory that holds them", r.opts.Binaries, strings.Join(missing, ", "))
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

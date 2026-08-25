package install

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// The config directory is the only one faramir creates whose parent can belong
// to the operator, and ensureDir chowns every ancestor it has to create. An
// absent parent is refused before anything is written rather than coming back
// root-owned.
func TestPreflightRefusesAConfigDirWhoseParentIsAbsent(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("preflight refuses root as the operator, so it never reaches this check")
	}
	base := t.TempDir()
	for _, tc := range []struct {
		name      string
		configDir string
		refused   bool
	}{
		{"the parent is absent", filepath.Join(base, "absent", "faramir"), true},
		// Reaches the later checks instead, which is all this asserts: the parent
		// being there is not what stops the run.
		{"the parent is there", filepath.Join(base, "faramir"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &runner{
				opts:   Options{AgentUser: me.Username, DryRun: true},
				layout: Layout{ConfigDir: tc.configDir},
			}

			err := run.preflight()

			parent := filepath.Dir(tc.configDir)
			refused := err != nil && strings.Contains(err.Error(), parent)
			if refused != tc.refused {
				t.Errorf("preflight() = %v, refused for %s = %v, want %v",
					err, parent, refused, tc.refused)
			}
		})
	}
}

// A symlink where the install asserts a mode or an owner would apply it to the
// target instead. Blocked before anything is written, so the answer is one
// message and an untouched host rather than a run that dies with the accounts
// created and no units.
func TestPreflightRefusesASymlinkedPath(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("preflight refuses root as the operator, so it never reaches this check")
	}
	for _, tc := range []struct {
		name string
		// link is relative to the config directory; "" puts it at LogDir instead.
		link  string
		isDir bool
		inLog string
	}{
		{name: "a managed secrets file", link: "secrets/prod.sops.yml"},
		{name: "the secrets directory", link: "secrets", isDir: true},
		{name: "the creation rule", link: ".sops.yaml"},
		{name: "the age key", link: "age.key"},
		{name: "the audit log", inLog: "audit.log"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			configDir := filepath.Join(base, "faramir")
			logDir := filepath.Join(base, "log")
			for _, dir := range []string{
				configDir, logDir,
				filepath.Join(configDir, "secrets"),
			} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// Somewhere the link can point that is not where it sits.
			target := filepath.Join(base, "elsewhere")
			if tc.isDir {
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(configDir, tc.link)
			if tc.inLog != "" {
				link = filepath.Join(logDir, tc.inLog)
			}
			if tc.isDir {
				if err := os.RemoveAll(link); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}

			run := &runner{
				opts: Options{AgentUser: me.Username, DryRun: true},
				layout: Layout{ConfigDir: configDir, LogDir: logDir,
					AgeKeyPath: filepath.Join(configDir, "age.key")},
			}

			err := run.preflight()
			if err == nil {
				t.Fatal("the run was allowed to start with a symlink in the tree")
			}
			if !strings.Contains(err.Error(), link) {
				t.Errorf("error does not name %s: %v", link, err)
			}
			if !strings.Contains(err.Error(), target) {
				t.Errorf("error does not say where the link points: %v", err)
			}
		})
	}
}

// Nothing linked, so the symlink check is not what stops the run.
func TestPreflightAllowsATreeWithNoSymlinks(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("preflight refuses root as the operator")
	}
	base := t.TempDir()
	configDir := filepath.Join(base, "faramir")
	logDir := filepath.Join(base, "log")
	for _, dir := range []string{
		configDir, logDir,
		filepath.Join(configDir, "secrets"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configDir, "secrets", "local.toml"),
		[]byte("# x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := &runner{
		opts:   Options{AgentUser: me.Username, DryRun: true},
		layout: Layout{ConfigDir: configDir, LogDir: logDir},
	}
	if err := run.refuseSymlinks(); err != nil {
		t.Errorf("refuseSymlinks() = %v, want nil for a tree with no links", err)
	}
}

// The operator cannot be one of faramir's own accounts. The arrangement rests on
// a brokered command running as a uid holding nothing the agent's holds, so an
// install where those are one account has no boundary to enforce: refused where
// the layout is validated, which is before anything is written.
//
// Nothing else caught it. The resolver refuses the service accounts as answers,
// but a name passed with --agent-user is the caller's own and outranks that; the
// loop beside this one holds the three daemons apart from each other and says
// nothing about the operator; and preflight asks only that the account is not
// root and exists.
func TestLayoutRefusesAnOperatorThatIsAServiceAccount(t *testing.T) {

	for _, tc := range []struct {
		name  string
		opts  Options
		names string
	}{
		{"the executor's own account", Options{AgentUser: DefaultExecUser}, "executor"},
		{"the broker's", Options{AgentUser: DefaultBrokerUser}, "broker"},
		{"the keeper's", Options{AgentUser: DefaultKeeperUser}, "keeper"},
		// A renamed daemon is refused under the name this run gives it, not the
		// compiled-in one: the flag decides the account here. A name no host has,
		// deliberately: the layout asks the passwd database nothing, so a test that
		// needed the account to exist would be one that passed on the machine it
		// was written on and nowhere else.
		{"a daemon moved onto an account of its own",
			Options{AgentUser: "faramir-runner", ExecUser: "faramir-runner"}, "executor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.DryRun = true
			tc.opts.ConfigDir = installDir(t)
			tc.opts.applyDefaults()
			_, err := tc.opts.layout()

			if err == nil {
				t.Fatalf("the layout accepted %q as the operator", tc.opts.AgentUser)
			}
			for _, want := range []string{tc.opts.AgentUser, tc.names} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not carry %q: %v", want, err)
				}
			}
		})
	}
}

// And the compiled-in name is an ordinary account on a host that moved that
// daemon elsewhere, so it must not be refused there: the names come from this
// run, not from the binary.
func TestLayoutAllowsADefaultNameWhenTheDaemonMoved(t *testing.T) {
	opts := Options{
		AgentUser: DefaultExecUser,
		ExecUser:  "faramir-runner",
		ConfigDir: t.TempDir(),
		DryRun:    true,
	}
	opts.applyDefaults()

	_, err := opts.layout()

	if err != nil && strings.Contains(err.Error(), "the executor runs as") {
		t.Errorf("%q was refused as the operator, but this run's executor is %q: %v",
			DefaultExecUser, "faramir-runner", err)
	}
}

// [command] concurrency is bounded at both ends by the loader, and preflight
// says so first: reaching the bound through the loader means a parse error
// about a file the operator never typed, raised after preflight has passed and
// the run looks like it is going ahead. Both ends, because a floor that only
// the loader knows is the ceiling's own argument turned around.
//
// Zero is not in the table on purpose. It is the unset signal every tunable
// shares, so applyDefaults turns it into the default before preflight sees it,
// and `--command-concurrency 0` installs the default rather than being refused.
func TestPreflightBoundsCommandConcurrency(t *testing.T) {
	agent := anyNonRootAccount(t)
	for _, tc := range []struct {
		name    string
		asked   int
		refused bool
	}{
		{"below the floor", -1, true},
		// Not refused: zero is the unset signal every tunable shares, and
		// applyDefaults has turned it into the default before preflight looks.
		// A caller that builds Options directly and never calls applyDefaults
		// leaves it at zero, and refusing that would refuse the run over a value
		// nobody typed.
		{"the unset signal", 0, false},
		{"at the floor", 1, false},
		{"at the ceiling", config.MaxConcurrentRuns, false},
		{"past the ceiling", config.MaxConcurrentRuns + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				AgentUser:          agent,
				DryRun:             true,
				ConfigDir:          filepath.Join(t.TempDir(), "faramir"),
				CommandConcurrency: tc.asked,
			}
			opts.applyDefaults()
			run := &runner{opts: opts, layout: Layout{ConfigDir: opts.ConfigDir}}

			err := run.preflight()

			// An accepted value reaches the later checks and fails on one of
			// those instead; what this asserts is which flag is named.
			refused := err != nil && strings.Contains(err.Error(), "--command-concurrency")
			if refused != tc.refused {
				t.Errorf("preflight() = %v, named --command-concurrency = %v, want %v",
					err, refused, tc.refused)
			}
		})
	}
}

// anyNonRootAccount is an account preflight will accept as the agent user. The
// other preflight tests take the current user, which makes them skip under
// root; this one asserts a bound that has nothing to do with who is running it,
// so it takes any account on the host that is not root instead and runs either
// way.
func anyNonRootAccount(t *testing.T) string {
	t.Helper()
	if me, err := user.Current(); err == nil && me.Username != "root" {
		return me.Username
	}
	for _, name := range []string{"nobody", "daemon", "bin"} {
		if userExists(name) {
			return name
		}
	}
	t.Skip("no non-root account on this host for preflight to accept")
	return ""
}

// The loader holds a question to the longest a brokered command may run, and
// does it quietly. `init` is where the two numbers are named together, so it is
// where an operator hears that the value they typed is not the one that will
// hold.
func TestInitWarnsWhenTheSudoTimeoutOutlastsTheLongestCommand(t *testing.T) {
	for _, tc := range []struct {
		name  string
		opts  Options
		warns bool
	}{
		{"a question longer than any command",
			Options{AllowSudo: true, SudoTimeoutSec: 900, CommandMaxTimeoutSec: 300}, true},
		{"a question inside it",
			Options{AllowSudo: true, SudoTimeoutSec: 120, CommandMaxTimeoutSec: 3600}, false},
		{"the two equal",
			Options{AllowSudo: true, SudoTimeoutSec: 300, CommandMaxTimeoutSec: 300}, false},
		{"no grant, so no question to hold",
			Options{SudoTimeoutSec: 900, CommandMaxTimeoutSec: 300}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &runner{opts: tc.opts}

			run.warnLongSudoTimeout()

			warned := len(run.report.Warnings) > 0
			if warned != tc.warns {
				t.Fatalf("warnings = %v, want warned=%v", run.report.Warnings, tc.warns)
			}
			if !warned {
				return
			}
			for _, want := range []string{"--sudo-timeout-sec 900", "300s", "--command-max-timeout-sec"} {
				if !strings.Contains(run.report.Warnings[0], want) {
					t.Errorf("the warning does not say %q: %s", want, run.report.Warnings[0])
				}
			}
		})
	}
}

// installDir is a temporary directory an install may be pointed at.
//
// t.TempDir() alone is not one: it lands under TMPDIR, and a config directory
// there is refused because every unit runs with PrivateTmp=true and would look
// for it in a /tmp of its own. That refusal is the subject of its own tests;
// here it would arrive first and hide whatever the test was actually asserting.
// So the check is lifted for the duration and put back after.
func installDir(t *testing.T) string {
	t.Helper()
	was := privateTmp
	privateTmp = nil
	t.Cleanup(func() { privateTmp = was })
	return t.TempDir()
}

// A config directory under /tmp installs and then serves nothing: PrivateTmp=
// gives each daemon a temporary hierarchy of its own, so what the install
// writes is in none of them. Refused before anything is written, the failure
// otherwise being three daemons that will not start and a directory sitting on
// disk exactly where the operator put it.
func TestAConfigDirUnderATemporaryHierarchyIsRefused(t *testing.T) {
	for _, dir := range []string{
		"/tmp", "/tmp/faramir", "/var/tmp", "/var/tmp/faramir/nested",
	} {
		opts := Options{
			AgentUser: "operator", ClientGroup: "shared", SecretsGroup: "store",
			BrokerUser: "br", KeeperUser: "kp", ExecUser: "ex", ConfigDir: dir,
		}
		opts.applyDefaults()

		_, err := opts.layout()

		if err == nil {
			t.Errorf("%s was accepted, and no daemon would find what it wrote", dir)
			continue
		}
		for _, want := range []string{"PrivateTmp", dir, DefaultConfigDir} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal does not say %q: %v", dir, want, err)
			}
		}
	}
	// A path that merely starts the same way is somewhere else entirely.
	for _, dir := range []string{"/tmpfiles", "/var/tmpdata", "/opt/tmp"} {
		opts := Options{
			AgentUser: "operator", ClientGroup: "shared", SecretsGroup: "store",
			BrokerUser: "br", KeeperUser: "kp", ExecUser: "ex", ConfigDir: dir,
		}
		opts.applyDefaults()
		if _, err := opts.layout(); err != nil {
			t.Errorf("%s was refused: %v", dir, err)
		}
	}
}

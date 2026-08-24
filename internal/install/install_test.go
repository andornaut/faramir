package install

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
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
			tc.opts.ConfigDir = t.TempDir()
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

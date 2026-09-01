package install

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/layouttest"
)

// sudoGrantLayout is testLayout with --allow-sudo passed.
func sudoGrantLayout(t *testing.T) hostlayout.Layout {
	t.Helper()
	opts := Options{
		AgentUser: "operator", ClientGroup: "shared", SecretsGroup: "store",
		BrokerUser: "br", KeeperUser: "kp", ExecUser: "ex",
		ConfigDir: "/opt/conf", AllowSudo: true,
	}
	opts.applyDefaults()
	layout, err := opts.layout()
	if err != nil {
		t.Fatal(err)
	}
	return layout
}

func loadRendered(t *testing.T, body []byte) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the config init writes does not load: %v\n%s", err, body)
	}
	return cfg
}

// Without --allow-sudo nothing is configured: no [sudo] section, so nothing is
// injected and no question can be raised. This is the promise the whole
// arrangement rests on: an install that did not ask for it is the install that
// existed before it.
func TestWithoutAllowSudoTheConfigCarriesNoSudoSection(t *testing.T) {
	layout := testLayout()
	if layout.AllowSudo {
		t.Error("AllowSudo is set with --allow-sudo unset")
	}
	body, err := agentcfg.Render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "[sudo]") {
		t.Errorf("the config carries a [sudo] section without --allow-sudo:\n%s", body)
	}
	if cfg := loadRendered(t, body); cfg.Sudo.ExecUser != "" {
		t.Errorf("exec_user = %q, want unset", cfg.Sudo.ExecUser)
	}
}

// With it, the section is there and every value points where the install put
// things.
func TestAllowSudoRendersTheSudoSection(t *testing.T) {
	layout := sudoGrantLayout(t)
	body, err := agentcfg.Render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadRendered(t, body)
	for _, check := range []struct{ name, got, want string }{
		{"exec_user", cfg.Sudo.ExecUser, layout.ExecUser},
		{"pam_service", cfg.Sudo.PamService, layout.PamService()},
		{"helper", cfg.Sudo.Helper, layout.PamHelper()},
	} {
		if check.got != check.want {
			t.Errorf("%s = %q, want %q", check.name, check.got, check.want)
		}
	}
	// Nothing is configured to ask: `faramir sudo approve` is where a question is seen.
	if len(cfg.Sudo.NotifyCommand) != 0 {
		t.Errorf("notify_command = %q, want nothing by default", cfg.Sudo.NotifyCommand)
	}
}

// There is no credential anywhere in an install that allows sudo: no file, no
// environment variable, nothing minted at start. This is the property the
// design turns on: an escalation that is a decision cannot be carried to a later
// command, because there is nothing to carry.
func TestASudoGrantPlacesNoCredential(t *testing.T) {
	layout := sudoGrantLayout(t)
	for _, asset := range []string{
		"etc/config.toml.tmpl", "etc/sudoers.tmpl", "etc/pam.d.tmpl",
		"agent/hooks/pam-escalate.tmpl", agentcfg.Units["faramir-broker.service"],
		agentcfg.Units["faramir-exec.service"],
	} {
		body, err := agentcfg.Render(asset, layout)
		if err != nil {
			t.Fatal(err)
		}
		for _, credential := range []string{
			"elevate.secret", "chpasswd", "elevate-rotate", "SUDO_ASKPASS",
		} {
			if strings.Contains(string(body), credential) {
				t.Errorf("%s mentions %q: escalation holds no credential", asset, credential)
			}
		}
	}
}

// The grant authenticates through PAM and caches nothing. NOPASSWD would skip
// PAM entirely, which is where the question is asked, so it is the one thing
// that must never appear here.
func TestTheSudoersGrantAuthenticatesThroughThePrivateService(t *testing.T) {
	layout := sudoGrantLayout(t)
	body, err := agentcfg.Render("etc/sudoers.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, rule := range []string{
		"ex ALL=(ALL:ALL) PASSWD: ALL",
		"Defaults:ex timestamp_timeout=0",
		// A refusal fails the auth step, which the stock mail_badpass would mail.
		"Defaults:ex !mail_badpass",
		// The private service is what confines a mistake to this one account, and
		// both launch types reach it: sudo authenticates `sudo -i` against a service
		// of its own.
		"Defaults:ex pam_service=faramir-sudo",
		"Defaults:ex pam_login_service=faramir-sudo",
	} {
		if !strings.Contains(text, rule) {
			t.Errorf("the sudoers file does not carry %q:\n%s", rule, text)
		}
	}
	// What root is given comes from a file root names, not from what the caller
	// happened to be holding. sudoers has an env_file that does this and sudo-rs
	// has no such setting, so it is read by pam_env in the service instead, on
	// every host. The literal path rather than layout.SudoEnvFile(), which is what
	// the template renders and so cannot disagree with it: this fixture puts the
	// config under /opt/conf, so the literal also says the file does not follow
	// --config-dir, an uninstall keeping that directory and never removing it whole.
	service, err := agentcfg.Render("etc/pam.d.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(service),
		"pam_env.so envfile=/usr/local/libexec/faramir/sudo-env") {
		t.Errorf("the PAM service does not read the environment file:\n%s", service)
	}
	if strings.Contains(text, "env_file=") {
		t.Errorf("the grant still names an env_file, which sudo-rs cannot parse:\n%s", text)
	}
	for line := range strings.Lines(text) {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "NOPASSWD") {
			t.Errorf("NOPASSWD skips PAM, which is where the question is asked: %q", line)
		}
		// env_keep would put the caller's own value back under the same name, which
		// is what env_reset threw away and why env_file is what this uses.
		if strings.Contains(line, "env_keep") {
			t.Errorf("env_keep preserves what the executor's uid was holding: %q", line)
		}
	}
}

// The sudo environment is the install's own: the operator it belongs to, and
// what [command] env configures. Rendered from a file the executor's uid cannot
// write, so none of it is the caller's word.
func TestTheSudoEnvironmentIsTheInstallsOwn(t *testing.T) {
	layout := sudoGrantLayout(t)
	layout.CommandEnv = map[string]string{"DEBIAN_FRONTEND": "noninteractive"}
	body, err := agentcfg.Render("etc/sudo-env.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		// SUDO_USER names the executor, which is nobody's identity: this is the
		// account whose host and home the run is about.
		"FARAMIR_OPERATOR=operator",
		"DEBIAN_FRONTEND=noninteractive",
	} {
		if !strings.Contains(string(body), line) {
			t.Errorf("the sudo environment does not carry %q:\n%s", line, body)
		}
	}
}

// Three ways a [command] env entry must not reach root. sudoers reads this file
// without env_keep or env_check, so what is filtered here is all that is
// filtered: before it existed, sudo's own env_reset stripped the last of them.
func TestTheSudoEnvironmentRefusesWhatWouldReachRootUnchecked(t *testing.T) {
	r := &runner{layout: sudoGrantLayout(t), fs: hostfs.FS{DryRun: true}}
	r.layout.CommandEnv = map[string]string{
		"SAFE": "yes",
		// --command-env splits on the first '=', so everything after one in the name
		// arrives as part of the name, a newline included.
		"SMUGGLE\nLD_PRELOAD": "/tmp/evil.so",
		// A value ends its own line, so a newline there does the same.
		"ALSO_SMUGGLE": "yes\nBASH_ENV=/tmp/evil.sh",
		// And '#' starts a comment anywhere on the line, so this would reach root
		// truncated rather than whole.
		"TRUNCATED": "before#after",
		// And a name env_refs refuses for the same reason this file must.
		"LD_LIBRARY_PATH": "/tmp/evil",
	}

	body, err := agentcfg.Render("etc/sudo-env.tmpl", r.sudoEnv())
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, refused := range []string{"LD_PRELOAD", "BASH_ENV", "LD_LIBRARY_PATH", "TRUNCATED"} {
		if strings.Contains(text, refused) {
			t.Errorf("%s reached root's environment:\n%s", refused, text)
		}
	}
	if !strings.Contains(text, "SAFE=yes") {
		t.Errorf("the rest of the file went with the refused entries:\n%s", text)
	}
}

// The PAM service is what confines a mistake, and carries the two words that
// decide whether it gates anything at all.
func TestThePamServiceGatesAndIsPrivate(t *testing.T) {
	layout := sudoGrantLayout(t)
	body, err := agentcfg.Render("etc/pam.d.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	// `requisite` on the helper, in both renderings. It is what makes a refusal
	// fatal where it is read rather than merely unsuccessful: anything softer and
	// the stack carries on to whatever permits below, which under sudo-rs is this
	// file's own pam_permit and under either is the password check in the stack
	// this one is reached from. Fatal here is also why a refusal does not rest on
	// the executor's password being locked -- that is a second boundary, checked
	// separately, and the stack must hold without it.
	for _, rs := range []bool{false, true} {
		variant := layout
		variant.SudoRs = rs
		rendered, renderErr := agentcfg.Render("etc/pam.d.tmpl", variant)
		if renderErr != nil {
			t.Fatal(renderErr)
		}
		for line := range strings.Lines(layouttest.Uncommented(string(rendered))) {
			if !strings.Contains(line, "pam_exec.so") {
				continue
			}
			if !strings.Contains(line, "requisite") {
				t.Errorf("sudo-rs=%v: the helper's line is not `requisite`: %q", rs,
					strings.TrimSpace(line))
			}
		}
	}
	// `seteuid`. Without it pam_exec runs the helper with the real uid, which
	// under setuid sudo is the executor's own, and the broker answers the escalate
	// op to root alone: the helper is refused and no escalation on the host works.
	if !strings.Contains(text, "seteuid") {
		t.Errorf("the helper runs without seteuid, so the broker refuses it and "+
			"every escalation on the host fails:\n%s", text)
	}
	if !strings.Contains(text, layout.PamHelper()) {
		t.Errorf("the service does not exec %s", layout.PamHelper())
	}
	// Private: named by the sudoers entry, and never the stock file.
	if layout.PamFile() == "/etc/pam.d/sudo" {
		t.Error("the service is /etc/pam.d/sudo, so a mistake reaches every account")
	}
}

// The helper is what the PAM service execs, and it runs the binary this install
// put on the host rather than whatever is on PATH.
func TestThePamHelperExecsTheInstalledBinary(t *testing.T) {
	layout := sudoGrantLayout(t)
	body, err := agentcfg.Render("agent/hooks/pam-escalate.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	want := "exec " + layout.BinDir + "/faramir pam-escalate"
	if !strings.Contains(string(body), want) {
		t.Errorf("the helper does not %q:\n%s", want, body)
	}
	if layout.PamHelper() != filepath.Join(layout.LibexecDir, "pam-escalate") {
		t.Errorf("the helper installs to %q, outside %q",
			layout.PamHelper(), layout.LibexecDir)
	}
}

// nnpImplied are the directives systemd documents as turning NoNewPrivileges=
// on whatever the unit says, each installing a seccomp filter, and a filter
// without CAP_SYS_ADMIN requires NNP. With NNP on, sudo is inert, so keeping
// any one of these does not harden the granting unit but turns the feature
// off.
var nnpImplied = []string{
	"DynamicUser",
	"LockPersonality",
	"MemoryDenyWriteExecute",
	"ProtectClock",
	"ProtectHostname",
	"ProtectKernelLogs",
	"ProtectKernelModules",
	"ProtectKernelTunables",
	"RestrictAddressFamilies",
	"RestrictNamespaces",
	"RestrictRealtime",
	"RestrictSUIDSGID",
	"SystemCallArchitectures",
	"SystemCallFilter",
}

// The executor's sandbox has to permit what an escalation is for. Two
// halves: the directives that bound root are dropped, and nothing is left that
// would put NoNewPrivileges= back.
func TestTheExecutorUnitPermitsAnApprovedSudo(t *testing.T) {
	plain := directives(t, "faramir-exec.service", testLayout())
	for _, tc := range []struct{ key, want string }{
		{"NoNewPrivileges", "true"},
		{"CapabilityBoundingSet", ""},
		{"ProtectSystem", "strict"},
		{"SystemCallFilter", "@system-service"},
	} {
		if got, set := plain[tc.key]; !set || got != tc.want {
			t.Errorf("without --allow-sudo the executor unit has %s=%q (set=%v), want %q",
				tc.key, got, set, tc.want)
		}
	}

	granted := directives(t, "faramir-exec.service", sudoGrantLayout(t))
	if granted["NoNewPrivileges"] != "false" {
		t.Errorf("with --allow-sudo NoNewPrivileges=%q: sudo is inert whatever the "+
			"sudoers file says", granted["NoNewPrivileges"])
	}
	// An explicit NoNewPrivileges=false that systemd overrides is worse than
	// none: the unit reads as though the grant works.
	for _, key := range nnpImplied {
		if value, set := granted[key]; set {
			t.Errorf("with --allow-sudo the executor unit sets %s=%q, which systemd "+
				"documents as implying NoNewPrivileges=yes: sudo would be inert and "+
				"every escalation would fail with 'effective uid is not 0'", key, value)
		}
	}
	// PrivateDevices implies it only when on, and the unit says so explicitly
	// because a PTY needs the devices either way.
	if got := granted["PrivateDevices"]; got != "false" {
		t.Errorf("with --allow-sudo PrivateDevices=%q, want an explicit false: true "+
			"implies NoNewPrivileges and children run on a PTY", got)
	}
	for _, gone := range []string{"CapabilityBoundingSet", "ProtectSystem"} {
		if value, set := granted[gone]; set {
			t.Errorf("with --allow-sudo the executor unit still sets %s=%q, so an approved "+
				"root cannot do what it was approved for", gone, value)
		}
	}
	// What bounds the uid below the escalation is unchanged.
	for _, tc := range []struct{ key, want string }{
		{"ProtectProc", "invisible"},
		{"UMask", "0007"},
		{"SupplementaryGroups", "shared"},
		{"AmbientCapabilities", ""},
		{"RemoveIPC", "true"},
	} {
		if got, set := granted[tc.key]; !set || got != tc.want {
			t.Errorf("with --allow-sudo the executor unit has %s=%q (set=%v), want %q: "+
				"that bounds this uid whether or not anything was approved",
				tc.key, got, set, tc.want)
		}
	}
}

// The executor unit delegates its cgroup on every install, a sudo grant or not: the
// executor confines each run to a cgroup of its own and reaps the whole cgroup
// when the run ends, so a setsid child cannot outlive it. That is the one
// mechanism that ends a run, so it is not conditional on the grant.
func TestTheExecutorUnitDelegatesItsCgroup(t *testing.T) {
	for _, layout := range []hostlayout.Layout{testLayout(), sudoGrantLayout(t)} {
		if got := directives(t, "faramir-exec.service", layout)["Delegate"]; got != "yes" {
			t.Errorf("Delegate=%q on the executor unit, want yes: without a delegated "+
				"cgroup the executor cannot confine a run and refuses to run it", got)
		}
	}
	// ProtectControlGroups= must not be set: it makes cgroupfs read-only, which
	// would stop the executor managing the per-run cgroup it now depends on.
	if value, set := directives(t, "faramir-exec.service", testLayout())["ProtectControlGroups"]; set {
		t.Errorf("the executor unit sets ProtectControlGroups=%q, which makes cgroupfs "+
			"read-only and breaks per-run confinement", value)
	}
	// Nor RestrictNamespaces=, at any value: systemd implements it as a seccomp rule
	// on clone()'s flags, cannot read the ones clone3() carries behind a pointer, and
	// so denies clone3() outright. The spawn above is CLONE_INTO_CGROUP, which
	// exists only there, so setting it stops every brokered command with ENOSYS.
	for _, layout := range []hostlayout.Layout{testLayout(), sudoGrantLayout(t)} {
		if value, set := directives(t, "faramir-exec.service", layout)["RestrictNamespaces"]; set {
			t.Errorf("the executor unit sets RestrictNamespaces=%q, so systemd denies "+
				"clone3() and the executor can spawn nothing", value)
		}
	}
}

// directives parses one rendered unit's KEY=VALUE lines, comments dropped. The
// last wins, as systemd takes it for a non-list directive.
func directives(t *testing.T, unit string, layout hostlayout.Layout) map[string]string {
	t.Helper()
	body, err := agentcfg.Render(agentcfg.Units[unit], layout)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for line := range strings.Lines(string(body)) {
		line = strings.TrimRight(line, "\n")
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.ContainsAny(key, " \t[") {
			continue
		}
		out[key] = value
	}
	return out
}

// The broker never runs a prompt, so it needs no hole in its sandbox: an
// escalation arrives over the socket it already serves. This is the check that
// the hole stays closed, systemd's ask-password directory being root-only and
// the reason that channel was not used.
func TestTheBrokerUnitNeedsNoHoleForEscalations(t *testing.T) {
	for _, layout := range []hostlayout.Layout{testLayout(), sudoGrantLayout(t)} {
		body, err := agentcfg.Render(agentcfg.Units["faramir-broker.service"], layout)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "ask-password") {
			t.Errorf("the broker unit opens systemd's ask-password directory; escalations "+
				"come over the broker socket and need nothing there:\n%s", body)
		}
	}
}

// notifyLayout is sudoGrantLayout with an announcement asked for.
func notifyLayout(t *testing.T, argv ...string) (hostlayout.Layout, error) {
	t.Helper()
	opts := Options{
		AgentUser: "operator", ClientGroup: "shared", SecretsGroup: "store",
		BrokerUser: "br", KeeperUser: "kp", ExecUser: "ex",
		ConfigDir: "/opt/conf", AllowSudo: true, NotifyCommand: argv,
	}
	opts.applyDefaults()
	return opts.layout()
}

// --notify-command is the flag the ownership implies. notify_command is init's,
// so a drop-in setting it is refused and an edit to config.toml is rewritten by
// the next run; the flag is what is left, and without one the value is
// unreachable on any host init runs on, which is every host under configuration
// management.
func TestNotifyCommandIsRenderedAndLoadsBack(t *testing.T) {
	layout, err := notifyLayout(t, "/usr/bin/wall", "{prompt}")
	if err != nil {
		t.Fatal(err)
	}
	body, err := agentcfg.Render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadRendered(t, body)
	want := []string{"/usr/bin/wall", "{prompt}"}
	if len(cfg.Sudo.NotifyCommand) != len(want) {
		t.Fatalf("notify_command = %q, want %q", cfg.Sudo.NotifyCommand, want)
	}
	for i := range want {
		if cfg.Sudo.NotifyCommand[i] != want[i] {
			t.Errorf("notify_command[%d] = %q, want %q", i, cfg.Sudo.NotifyCommand[i], want[i])
		}
	}
}

// An argument the operator wrote reaches a TOML file, and one the loader cannot
// parse is a broker that will not start. TOML takes a shorter set of escapes
// than Go, rejecting \a and \v rather than misreading them, so this holds the
// renderer's quoting to surviving the round trip.
func TestNotifyCommandSurvivesQuotingItsArguments(t *testing.T) {
	for _, awkward := range []string{
		"it said \"{prompt}\" \\ here",
		"bell \a {prompt}",
		"vertical \v {prompt}",
		"tab \t and newline \n {prompt}",
		"del \x7f and nul-adjacent \x01 {prompt}",
	} {
		t.Run(strconv.Quote(awkward), func(t *testing.T) {
			checkNotifyRoundTrip(t, awkward)
		})
	}
}

func checkNotifyRoundTrip(t *testing.T, awkward string) {
	t.Helper()
	layout, err := notifyLayout(t, "/usr/bin/wall", awkward)
	if err != nil {
		t.Fatal(err)
	}
	body, err := agentcfg.Render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadRendered(t, body)
	if len(cfg.Sudo.NotifyCommand) != 2 || cfg.Sudo.NotifyCommand[1] != awkward {
		t.Errorf("notify_command = %q, want the second argument back as %q",
			cfg.Sudo.NotifyCommand, awkward)
	}
}

// Blocked at install rather than at the daemon's next start. init is the only
// writer of this key, so a value it accepts and the loader will not is an install
// that reported success and left the broker unable to come up.
func TestAnUnusableNotifyCommandIsRefusedByInit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		argv  []string
		sudo  bool
		wants string
	}{
		{
			name: "names neither placeholder", argv: []string{"/usr/bin/wall", "something"},
			sudo: true, wants: "neither {prompt} nor {id}",
		},
		{
			name: "without a grant to announce", argv: []string{"/usr/bin/wall", "{prompt}"},
			sudo: false, wants: "--allow-sudo",
		},
		{
			name: "a program that is not on PATH", argv: []string{"no-such-notifier", "{prompt}"},
			sudo: true, wants: "is not on PATH",
		},
		{
			// The same typo spelled absolutely. Resolution cannot catch this one, an
			// absolute path being taken as given, so it is refused for not being
			// there instead: one mistake must not have a spelling that gets through.
			name: "an absolute path that is not there",
			argv: []string{"/usr/bin/no-such-notifier", "{prompt}"},
			sudo: true, wants: "is not there",
		},
		{
			name: "a directory", argv: []string{"/tmp", "{prompt}"},
			sudo: true, wants: "not an executable file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				AgentUser: "operator", ClientGroup: "shared", SecretsGroup: "store",
				BrokerUser: "br", KeeperUser: "kp", ExecUser: "ex",
				ConfigDir: "/opt/conf", AllowSudo: tc.sudo, NotifyCommand: tc.argv,
			}
			opts.applyDefaults()
			_, err := opts.layout()
			if err == nil {
				t.Fatalf("init accepted %q, which the broker cannot use", tc.argv)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("error does not say %q: %v", tc.wants, err)
			}
		})
	}
}

// Resolved at install time, as ssh_agent and ssh_add are and for the same
// reason: the broker execs this as the uid holding every decrypted value, so
// which file a bare name reaches is decided here rather than by the broker's
// PATH at the moment a question is raised.
func TestNotifyCommandIsPinnedToAPathAtInstallTime(t *testing.T) {
	layout, err := notifyLayout(t, "sh", "{prompt}")
	if err != nil {
		t.Fatal(err)
	}
	if got := layout.NotifyCommand[0]; !filepath.IsAbs(got) {
		t.Errorf("notify_command[0] = %q, want it resolved to a path", got)
	}
	// The arguments are the operator's and are left alone.
	if got := layout.NotifyCommand[1]; got != "{prompt}" {
		t.Errorf("notify_command[1] = %q, want it untouched", got)
	}
}

// A clean install says nothing about the sudo environment. PATH is both a
// [command] env default and a name sudo sets itself, so warning about it would
// put a line on every install that names nothing the operator did -- in the
// channel that has to carry the entries which would really have reached root.
func TestAStockSudoEnvironmentIsQuiet(t *testing.T) {
	r := &runner{layout: sudoGrantLayout(t)}
	r.layout.CommandEnv = map[string]string{
		"PATH": "/usr/bin:/bin", "TERM": "xterm", "LANG": "C.UTF-8",
		"LC_ALL": "C.UTF-8", "DEBIAN_FRONTEND": "noninteractive",
	}
	env := r.sudoEnv()

	if _, kept := env.CommandEnv["PATH"]; kept {
		t.Error("PATH reached the sudo environment; sudo's secure_path is what sets it")
	}
	if len(r.report.Warnings) != 0 {
		t.Errorf("a stock install warned: %v", r.report.Warnings)
	}
	// And the ones that are neither reserved nor unsafe are still there.
	if env.CommandEnv["DEBIAN_FRONTEND"] != "noninteractive" {
		t.Errorf("CommandEnv = %v, want the entries sudo does not set itself", env.CommandEnv)
	}
}

// But a name that would really have reached root still says so: that is what the
// warning is for, and quieting PATH must not quiet these.
func TestAReservedNameThatWouldReachRootIsReported(t *testing.T) {
	r := &runner{layout: sudoGrantLayout(t)}
	r.layout.CommandEnv = map[string]string{"LD_PRELOAD": "/tmp/evil.so"}
	if env := r.sudoEnv(); len(env.CommandEnv) != 0 {
		t.Errorf("CommandEnv = %v, want LD_PRELOAD left out", env.CommandEnv)
	}
	if len(r.report.Warnings) == 0 {
		t.Error("LD_PRELOAD was dropped without a word, so nobody learns it was ignored")
	}
}

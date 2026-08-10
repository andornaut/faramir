package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// elevatingLayout is testLayout with --elevate passed.
func elevatingLayout(t *testing.T) Layout {
	t.Helper()
	opts := Options{
		OperatorUser: "operator", ClientGroup: "shared", SecretsGroup: "store",
		BrokerUser: "br", KeeperUser: "kp", ExecUser: "ex",
		ConfigDir: "/opt/conf", Elevate: true,
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

// Without --elevate nothing is configured: no [elevate] section, so nothing is
// injected and no question can be raised.  This is the promise the whole
// arrangement rests on -- an install that did not ask for it is the install
// that existed before it.
func TestWithoutElevateTheConfigCarriesNoElevateSection(t *testing.T) {
	layout := testLayout()
	if layout.Elevate {
		t.Error("Elevate is set with --elevate unset")
	}
	body, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "[elevate]") {
		t.Errorf("the config carries an [elevate] section without --elevate:\n%s", body)
	}
	if cfg := loadRendered(t, body); cfg.Elevate.ExecUser != "" {
		t.Errorf("exec_user = %q, want unset", cfg.Elevate.ExecUser)
	}
}

// With it, the section is there and every value points where the install put
// things.
func TestElevateRendersTheElevateSection(t *testing.T) {
	layout := elevatingLayout(t)
	body, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadRendered(t, body)
	for _, check := range []struct{ name, got, want string }{
		{"exec_user", cfg.Elevate.ExecUser, layout.ExecUser},
		{"pam_service", cfg.Elevate.PamService, layout.PamService()},
		{"helper", cfg.Elevate.Helper, layout.PamHelper()},
	} {
		if check.got != check.want {
			t.Errorf("%s = %q, want %q", check.name, check.got, check.want)
		}
	}
	// Nothing is configured to ask: `faramir approve` is where a question is seen.
	if len(cfg.Elevate.NotifyCommand) != 0 {
		t.Errorf("notify_command = %q, want nothing by default", cfg.Elevate.NotifyCommand)
	}
}

// There is no credential anywhere in an elevating install: no file, no
// environment variable, nothing minted at start.  This is the property the
// design turns on -- an approval that is a decision cannot be carried to a
// later command, because there is nothing to carry.
func TestAnElevatingInstallPlacesNoCredential(t *testing.T) {
	layout := elevatingLayout(t)
	for _, asset := range []string{
		"etc/config.toml.tmpl", "etc/sudoers.tmpl", "etc/pam.d.tmpl",
		"agent/hooks/pam-approve.tmpl", units["faramir-broker.service"],
		units["faramir-exec.service"],
	} {
		body, err := render(asset, layout)
		if err != nil {
			t.Fatal(err)
		}
		for _, credential := range []string{
			"elevate.secret", "chpasswd", "elevate-rotate", "SUDO_ASKPASS",
		} {
			if strings.Contains(string(body), credential) {
				t.Errorf("%s mentions %q: elevation holds no credential", asset, credential)
			}
		}
	}
}

// The grant authenticates through PAM and caches nothing.  NOPASSWD would skip
// PAM entirely, which is where the question is asked, so it is the one thing
// that must never appear here.
func TestTheSudoersGrantAuthenticatesThroughThePrivateService(t *testing.T) {
	layout := elevatingLayout(t)
	body, err := render("etc/sudoers.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, rule := range []string{
		"ex ALL=(ALL:ALL) PASSWD: ALL",
		"Defaults:ex timestamp_timeout=0",
		// The private service is what confines a mistake to this one account.
		"Defaults:ex pam_service=faramir-sudo",
	} {
		if !strings.Contains(text, rule) {
			t.Errorf("the sudoers file does not carry %q:\n%s", rule, text)
		}
	}
	for line := range strings.Lines(text) {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "NOPASSWD") {
			t.Errorf("NOPASSWD skips PAM, which is where the question is asked: %q", line)
		}
	}
}

// The PAM service is what confines a mistake, and carries the two words that
// decide whether it gates anything at all.
func TestThePamServiceGatesAndIsPrivate(t *testing.T) {
	layout := elevatingLayout(t)
	body, err := render("etc/pam.d.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	// `requisite`, never `sufficient`.  With sufficient a helper that REFUSES is
	// not fatal, the stack falls through to pam_permit below, and every elevation
	// is granted without asking anybody -- demonstrated on a live host before
	// this design was chosen.
	if !strings.Contains(text, "auth     requisite  pam_exec.so") {
		t.Errorf("the auth line is not `requisite`:\n%s", text)
	}
	for line := range strings.Lines(text) {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "sufficient") {
			t.Errorf("a `sufficient` control flag makes a refusal non-fatal: %q", line)
		}
	}
	// `seteuid`.  Without it pam_exec runs the helper with the real uid, which
	// under setuid sudo is the executor's own, and the broker answers the elevate
	// op to root alone: the helper is refused and no elevation on the host works.
	if !strings.Contains(text, "seteuid") {
		t.Errorf("the helper runs without seteuid, so the broker refuses it and "+
			"every elevation on the host fails:\n%s", text)
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
	layout := elevatingLayout(t)
	body, err := render("agent/hooks/pam-approve.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	want := "exec " + layout.BinDir + "/faramir pam-approve"
	if !strings.Contains(string(body), want) {
		t.Errorf("the helper does not %q:\n%s", want, body)
	}
	if layout.PamHelper() != filepath.Join(layout.LibexecDir, "pam-approve") {
		t.Errorf("the helper installs to %q, outside %q",
			layout.PamHelper(), layout.LibexecDir)
	}
}

// nnpImplied are the directives systemd documents as turning NoNewPrivileges=
// on whatever the unit says, because each installs a seccomp filter and a
// filter without CAP_SYS_ADMIN requires NNP.  With NNP on, sudo is inert.
//
// Written out rather than grepped for, because this is the check that the
// elevating unit's NoNewPrivileges=false is not quietly overridden: keeping any
// one of these does not harden the unit, it turns the feature off.
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

// The executor's sandbox has to permit what an approved elevation is for.  Two
// halves: the directives that bound root are dropped, and nothing is left that
// would put NoNewPrivileges= back.
func TestTheExecutorUnitPermitsAnApprovedElevation(t *testing.T) {
	plain := directives(t, "faramir-exec.service", testLayout())
	for key, want := range map[string]string{
		"NoNewPrivileges":       "true",
		"CapabilityBoundingSet": "",
		"ProtectSystem":         "strict",
		"SystemCallFilter":      "@system-service",
	} {
		if got, set := plain[key]; !set || got != want {
			t.Errorf("without --elevate the executor unit has %s=%q (set=%v), want %q",
				key, got, set, want)
		}
	}

	elevating := directives(t, "faramir-exec.service", elevatingLayout(t))
	if elevating["NoNewPrivileges"] != "false" {
		t.Errorf("with --elevate NoNewPrivileges=%q: sudo is inert whatever the "+
			"sudoers file says", elevating["NoNewPrivileges"])
	}
	// The finding this test exists for: an explicit NoNewPrivileges=false that
	// systemd overrides is worse than none, because the unit reads as though the
	// grant works.
	for _, key := range nnpImplied {
		if value, set := elevating[key]; set {
			t.Errorf("with --elevate the executor unit sets %s=%q, which systemd "+
				"documents as implying NoNewPrivileges=yes: sudo would be inert and "+
				"every elevation would fail with 'effective uid is not 0'", key, value)
		}
	}
	// PrivateDevices implies it only when on, and the unit says so explicitly
	// because a PTY needs the devices either way.
	if got := elevating["PrivateDevices"]; got != "false" {
		t.Errorf("with --elevate PrivateDevices=%q, want an explicit false: true "+
			"implies NoNewPrivileges and children run on a PTY", got)
	}
	for _, gone := range []string{"CapabilityBoundingSet", "ProtectSystem"} {
		if value, set := elevating[gone]; set {
			t.Errorf("with --elevate the executor unit still sets %s=%q, so an approved "+
				"root cannot do what it was approved for", gone, value)
		}
	}
	// What bounds the uid below the approval is unchanged.
	for key, want := range map[string]string{
		"ProtectProc":         "invisible",
		"UMask":               "0007",
		"SupplementaryGroups": "shared",
		"AmbientCapabilities": "",
		"RemoveIPC":           "true",
	} {
		if got, set := elevating[key]; !set || got != want {
			t.Errorf("with --elevate the executor unit has %s=%q (set=%v), want %q: "+
				"that bounds this uid whether or not anything was approved",
				key, got, set, want)
		}
	}
}

// The executor unit delegates its cgroup on every install, elevation or not: the
// executor confines each run to a cgroup of its own and reaps the whole cgroup
// when the run ends, so a setsid child cannot outlive it.  That is the one
// mechanism that ends a run, so it is not conditional on the grant.
func TestTheExecutorUnitDelegatesItsCgroup(t *testing.T) {
	for _, layout := range []Layout{testLayout(), elevatingLayout(t)} {
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
}

// directives parses one rendered unit's KEY=VALUE lines, comments dropped.  The
// last wins, as systemd takes it for a non-list directive.
func directives(t *testing.T, unit string, layout Layout) map[string]string {
	t.Helper()
	body, err := render(units[unit], layout)
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
// approval arrives over the socket it already serves.  This is the check that
// the hole stays closed, systemd's ask-password directory being root-only and
// the reason that channel was not used.
func TestTheBrokerUnitNeedsNoHoleForApprovals(t *testing.T) {
	for _, layout := range []Layout{testLayout(), elevatingLayout(t)} {
		body, err := render(units["faramir-broker.service"], layout)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "ask-password") {
			t.Errorf("the broker unit opens systemd's ask-password directory; approvals "+
				"come over the broker socket and need nothing there:\n%s", body)
		}
	}
}

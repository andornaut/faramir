package install

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// writeInstalledConfig lays down enough of a config.toml for Load to parse, and
// nothing this does not read: the point is what init takes back off an install,
// not what a broker needs to run.
func writeInstalledConfig(t *testing.T, dir, group, sshKey string) {
	t.Helper()
	body := "[server]\nallowed_group = \"" + group + "\"\n\n[ssh]\nkey = \"" + sshKey + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// config.toml is rendered from these values on every run and a drop-in may not
// set them, so a flag left out has to mean "what the install uses" rather than
// the compiled-in default: the alternative rewrites allowed_group and mints a
// key at a path no managed host authorizes.
func TestAdoptInstalledTakesWhatWasNotNamed(t *testing.T) {
	dir := t.TempDir()
	writeInstalledConfig(t, dir, "devs", "/srv/keys/fleet_ed25519")
	opts := Options{ConfigDir: dir}

	took, err := opts.adoptInstalled()

	if err != nil {
		t.Fatal(err)
	}
	if opts.ClientGroup != "devs" {
		t.Errorf("ClientGroup = %q, want devs: a re-run would have locked the group out "+
			"of the broker socket", opts.ClientGroup)
	}
	if opts.SSHKey != "/srv/keys/fleet_ed25519" {
		t.Errorf("SSHKey = %q, want the installed path: a re-run would have minted a key "+
			"no managed host authorizes", opts.SSHKey)
	}
	report := strings.Join(took, ", ")
	for _, want := range []string{"--client-group devs", "--ssh-key /srv/keys/fleet_ed25519"} {
		if !strings.Contains(report, want) {
			t.Errorf("report does not say %q: %s", want, report)
		}
	}
}

// A flag is how any of these is changed, so naming one outranks the install.
func TestAdoptInstalledLeavesWhatWasNamedAlone(t *testing.T) {
	dir := t.TempDir()
	writeInstalledConfig(t, dir, "devs", "/srv/keys/fleet_ed25519")
	opts := Options{ConfigDir: dir, ClientGroup: "other", SSHKey: "/srv/keys/other"}

	took, _ := opts.adoptInstalled()

	if opts.ClientGroup != "other" || opts.SSHKey != "/srv/keys/other" {
		t.Errorf("adoption overrode the flags: group %q, key %q", opts.ClientGroup, opts.SSHKey)
	}
	report := strings.Join(took, ", ")
	if strings.Contains(report, "devs") || strings.Contains(report, "fleet_ed25519") {
		t.Errorf("reported adopting what the flags named: %s", report)
	}
}

// An install that took every default has nothing a flag would have reverted, so
// there is nothing to report and the line stays off.
func TestAdoptInstalledIsQuietAboutTheDefaults(t *testing.T) {
	dir := t.TempDir()
	writeInstalledConfig(t, dir, DefaultClientGroup, filepath.Join(dir, "id_ed25519"))
	opts := Options{ConfigDir: dir}

	took, err := opts.adoptInstalled()

	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range took {
		if strings.HasPrefix(entry, "--client-group") || strings.HasPrefix(entry, "--ssh-key") {
			t.Errorf("reported %q, which is what the defaults produce anyway", entry)
		}
	}
}

// The first install has nothing to adopt from, which is what the compiled-in
// defaults are for and not a fault to report.
func TestAdoptInstalledSaysNothingOnAFirstInstall(t *testing.T) {
	opts := Options{ConfigDir: t.TempDir()}

	took, err := opts.adoptInstalled()

	if err != nil {
		t.Fatalf("refused a host with no install: %v", err)
	}
	if opts.ClientGroup != "" || opts.SSHKey != "" {
		t.Errorf("invented values from an absent config: group %q, key %q",
			opts.ClientGroup, opts.SSHKey)
	}
	for _, entry := range took {
		if strings.HasPrefix(entry, "--client-group") || strings.HasPrefix(entry, "--ssh-key") {
			t.Errorf("reported %q with no config to read it from", entry)
		}
	}
}

// A config that is there and will not parse is refused. Carrying on would render
// the client group and the key from the compiled-in defaults, which is the
// reversion this exists to prevent, and the file is the operator's to fix or
// remove.
func TestAdoptInstalledRefusesAConfigItCannotRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"),
		[]byte("[server\nallowed_group = \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := Options{ConfigDir: dir}

	_, err := opts.adoptInstalled()

	if err == nil {
		t.Fatal("read nothing and carried on, which reverts the install silently")
	}
	for _, want := range []string{"does not load", "Fix the file", "remove it to install fresh"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not say %q: %v", want, err)
		}
	}
}

// Naming everything the file answers for is not a way past it. The reason to
// stop is the broken install, not what this run happened to need read.
func TestAdoptInstalledRefusesAnUnreadableConfigEvenWhenNothingIsNeeded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"),
		[]byte("[server\nallowed_group = \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		ConfigDir: dir, ClientGroup: "devs", SSHKey: "/srv/keys/fleet_ed25519",
		BrokerUser: "b", KeeperUser: "k", ExecUser: "e", SecretsGroup: "s",
	}

	if _, err := opts.adoptInstalled(); err == nil {
		t.Fatal("re-provisioned over a config that does not parse")
	}
}

// writeNotifierConfig lays down an install that named a notifier, and nothing
// else: what this asks is whether a re-run keeps the announcement.
func writeNotifierConfig(t *testing.T, dir string, argv ...string) {
	t.Helper()
	quoted := make([]string, 0, len(argv))
	for _, arg := range argv {
		quoted = append(quoted, strconv.Quote(arg))
	}
	body := "[sudo]\nnotify_command = [" + strings.Join(quoted, ", ") + "]\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// notify_command is rendered from this value like every other one, so a bare
// re-run that dropped it would leave a host where a question waits and nothing
// says so. The flag is the only way onto a host -- a drop-in setting it is
// refused -- which is why it is read back rather than retyped every run.
func TestAdoptInstalledKeepsTheNotifier(t *testing.T) {
	dir := t.TempDir()
	writeNotifierConfig(t, dir, "/usr/bin/wall", "{prompt}")
	opts := Options{ConfigDir: dir, AllowSudo: true}

	took, err := opts.adoptInstalled()

	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/wall", "{prompt}"}
	if !slices.Equal(opts.NotifyCommand, want) {
		t.Errorf("NotifyCommand = %q, want %q: a re-run would have installed a host "+
			"that announces nothing", opts.NotifyCommand, want)
	}
	report := strings.Join(took, ", ")
	if !strings.Contains(report, "--notify-command /usr/bin/wall --notify-command {prompt}") {
		t.Errorf("report does not say what it took, one argument per flag: %s", report)
	}
}

// The flag outranks the install here as everywhere, and it replaces rather than
// adds: an operator naming a new notifier is naming the whole argv.
func TestAdoptInstalledLeavesANamedNotifierAlone(t *testing.T) {
	dir := t.TempDir()
	writeNotifierConfig(t, dir, "/usr/bin/wall", "{prompt}")
	opts := Options{
		ConfigDir: dir, AllowSudo: true,
		NotifyCommand: []string{"/usr/local/bin/push", "{id}"},
	}

	took, err := opts.adoptInstalled()

	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/local/bin/push", "{id}"}
	if !slices.Equal(opts.NotifyCommand, want) {
		t.Errorf("NotifyCommand = %q, want %q", opts.NotifyCommand, want)
	}
	if strings.Contains(strings.Join(took, ", "), "wall") {
		t.Errorf("reported adopting what the flag named: %s", took)
	}
}

// Re-running without --allow-sudo takes the grant back, and the announcement
// belongs to it: no [sudo] section is written, so there is nothing to announce
// and nothing to keep. Adopting it anyway would refuse the run over a value
// that would not have been rendered.
func TestAdoptInstalledDropsTheNotifierWithTheGrant(t *testing.T) {
	dir := t.TempDir()
	writeNotifierConfig(t, dir, "/usr/bin/wall", "{prompt}")
	opts := Options{ConfigDir: dir}

	took, err := opts.adoptInstalled()

	if err != nil {
		t.Fatal(err)
	}
	if len(opts.NotifyCommand) != 0 {
		t.Errorf("NotifyCommand = %q on a run that grants no sudo, which init refuses",
			opts.NotifyCommand)
	}
	if strings.Contains(strings.Join(took, ", "), "--notify-command") {
		t.Errorf("reported keeping an announcement this run writes no section for: %s", took)
	}
}

// A first install has no notifier to read, and the absence is the default
// rather than something to report.
func TestAdoptInstalledInventsNoNotifier(t *testing.T) {
	dir := t.TempDir()
	writeInstalledConfig(t, dir, DefaultClientGroup, filepath.Join(dir, "id_ed25519"))
	opts := Options{ConfigDir: dir, AllowSudo: true}

	took, err := opts.adoptInstalled()

	if err != nil {
		t.Fatal(err)
	}
	if len(opts.NotifyCommand) != 0 {
		t.Errorf("NotifyCommand = %q with none installed", opts.NotifyCommand)
	}
	if strings.Contains(strings.Join(took, ", "), "--notify-command") {
		t.Errorf("reported a notifier no config named: %s", took)
	}
}

// The loop closed: what init renders is what the next init reads back, awkward
// quoting included. The two halves are written apart -- the template quotes,
// the loader parses -- and an argument that survives one but not the other
// would be a notifier silently changed by a re-run.
func TestTheRenderedNotifierIsAdoptedBack(t *testing.T) {
	want := []string{"/usr/bin/wall", "it said \"{prompt}\" \\ here"}
	layout, err := notifyLayout(t, want...)
	if err != nil {
		t.Fatal(err)
	}
	body, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{ConfigDir: dir, AllowSudo: true}

	if _, err := opts.adoptInstalled(); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(opts.NotifyCommand, want) {
		t.Errorf("NotifyCommand = %q, want %q: a re-run changed the notifier it read",
			opts.NotifyCommand, want)
	}
}

// A notifier read back off the install is one the operator did not type on this
// run, so the refusal has to point at the config rather than at a flag that is
// not in their command line. The value is still held to the same rules a typed
// one is: an install that wrote a notifier which is not there would come up
// announcing nothing, which is the failure the check exists for.
func TestAnAdoptedNotifierIsRefusedInItsOwnName(t *testing.T) {
	dir := installDir(t)
	gone := filepath.Join(dir, "notifier-that-was-uninstalled")
	writeNotifierConfig(t, dir, gone, "{prompt}")
	opts := Options{
		AgentUser: "operator", ClientGroup: "shared", SecretsGroup: "store",
		BrokerUser: "br", KeeperUser: "kp", ExecUser: "ex",
		ConfigDir: dir, AllowSudo: true,
	}
	if _, err := opts.adoptInstalled(); err != nil {
		t.Fatal(err)
	}
	opts.applyDefaults()

	_, err := opts.layout()

	if err == nil {
		t.Fatal("wrote a config naming a notifier that is not installed")
	}
	for _, want := range []string{"notify_command", gone, "is not there", "--notify-command"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not say %q: %v", want, err)
		}
	}
	if strings.HasPrefix(err.Error(), "--notify-command") {
		t.Errorf("the refusal opens by naming a flag this run did not carry: %v", err)
	}
}

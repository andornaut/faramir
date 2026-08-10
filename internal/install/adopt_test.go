package install

import (
	"os"
	"path/filepath"
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

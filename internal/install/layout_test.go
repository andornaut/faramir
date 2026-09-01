package install

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
)

// The key follows the config directory, so an encrypted home holding the
// secrets directory holds the key too and a powered-off disk carries neither.
func TestAgeKeyFollowsTheConfigDir(t *testing.T) {
	for _, tc := range []struct{ name, configDir, wantKey, wantDir string }{
		{"the default", hostlayout.DefaultConfigDir, hostlayout.DefaultConfigDir + "/age.key", hostlayout.DefaultConfigDir},
		{"an agent account's home", "/home/op/.config/faramir", "/home/op/.config/faramir/age.key", "/home/op/.config/faramir"},
		{"a trailing slash is cleaned", "/srv/f/", "/srv/f/age.key", "/srv/f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				AgentUser: "op", ClientGroup: hostlayout.DefaultClientGroup,
				BrokerUser: hostlayout.DefaultBrokerUser, KeeperUser: hostlayout.DefaultKeeperUser,
				ExecUser:  hostlayout.DefaultExecUser,
				ConfigDir: tc.configDir,
			}
			layout, err := opts.layout()
			if err != nil {
				t.Fatal(err)
			}
			if layout.AgeKeyPath != tc.wantKey {
				t.Errorf("AgeKeyPath = %q, want %q", layout.AgeKeyPath, tc.wantKey)
			}
			// The config directory, created for the config anyway.
			if got := layout.AgeKeyDir(); got != tc.wantDir {
				t.Errorf("AgeKeyDir = %q, want %q", got, tc.wantDir)
			}
			if layout.AgeKeyDir() != layout.ConfigDir {
				t.Errorf("AgeKeyDir %q is not the config directory %q",
					layout.AgeKeyDir(), layout.ConfigDir)
			}
		})
	}
}

// The secrets group is the keeper's own, so the accounts that can read the
// ciphertext are the one that decrypts it, with no membership list to keep.
func TestStoreGroupDefaultsToTheKeepersOwn(t *testing.T) {
	for _, tc := range []struct{ name, keeperUser, storeGroup, want string }{
		{"the default", "", "", hostlayout.DefaultKeeperUser},
		{"a renamed keeper takes its group with it", "vault", "", "vault"},
		{"an explicit group is honoured", "", "faramir-secrets", "faramir-secrets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				AgentUser: "op", KeeperUser: tc.keeperUser, SecretsGroup: tc.storeGroup,
			}
			opts.applyDefaults()
			if opts.SecretsGroup != tc.want {
				t.Errorf("SecretsGroup = %q, want %q", opts.SecretsGroup, tc.want)
			}
		})
	}
}

// The creation rule sits in the config directory, not the secrets directory.
// sops walks up from the working directory, so it is found from both, and the
// secrets directory stays nothing but ciphertext: the managed store globs it and
// filepath.Glob matches dotfiles.
func TestSopsConfigSitsAboveTheStore(t *testing.T) {
	layout := hostlayout.Layout{ConfigDir: "/etc/faramir"}
	if got, want := layout.SopsConfigPath(), "/etc/faramir/.sops.yaml"; got != want {
		t.Errorf("SopsConfigPath = %q, want %q", got, want)
	}
	if dir := filepath.Dir(layout.SopsConfigPath()); dir != layout.ConfigDir {
		t.Errorf("rule file is in %q, not the config directory %q", dir, layout.ConfigDir)
	}
	if filepath.Dir(layout.SopsConfigPath()) == layout.SecretsDir() {
		t.Error("the rule file is in the secrets directory, where the [secret] glob reaches it")
	}
	// The upward search reaches it from the secrets directory.
	if !strings.HasPrefix(layout.SecretsDir(), layout.ConfigDir+string(filepath.Separator)) {
		t.Errorf("store %q is not under the config directory %q, so the upward "+
			"search would not reach the rule", layout.SecretsDir(), layout.ConfigDir)
	}
	// Named so doctor can report a copy that would shadow this one.
	if got, want := layout.StaleSopsConfigPath(), "/etc/faramir/secrets/.sops.yaml"; got != want {
		t.Errorf("StaleSopsConfigPath = %q, want %q", got, want)
	}
}

// Asking for a value by name and reading the file it comes from are different
// privileges, and the agent's account holds the first.
func TestStoreGroupIsNotTheClientGroup(t *testing.T) {
	opts := Options{AgentUser: "op"}
	opts.applyDefaults()
	if opts.SecretsGroup == opts.ClientGroup {
		t.Errorf("secrets group and client group are both %q", opts.ClientGroup)
	}
}

// A path holding a control character is refused on the way in.
//
// These reach three formats with three escape sets: the agents' JSON settings,
// config.toml, and the deny patterns. A renderer that escapes for the wrong one
// writes a file its reader rejects, and for the settings that reads as an
// enrolment that worked with every rule in it missing. Refusing the input is one
// check instead of three, and it is the only one that cannot be got wrong
// somewhere new.
func TestAPathWithAControlCharacterIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, dir, key string }{
		{"bell in the config dir", "/etc/far\amir", ""},
		{"vertical tab in the config dir", "/etc/far\vmir", ""},
		{"a C0 byte in the config dir", "/etc/far\x01mir", ""},
		{"DEL in the config dir", "/etc/far\x7fmir", ""},
		{"invalid UTF-8 in the config dir", "/etc/far\xffmir", ""},
		{"bell in the ssh key path", "/etc/faramir", "/etc/faramir/id\aed25519"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				AgentUser: "operator", ClientGroup: "shared", SecretsGroup: "store",
				BrokerUser: "br", KeeperUser: "kp", ExecUser: "ex",
				ConfigDir: tc.dir, SSHKey: tc.key,
			}
			opts.applyDefaults()
			if _, err := opts.layout(); err == nil {
				t.Fatalf("accepted %q / %q, which no rendered format takes literally",
					tc.dir, tc.key)
			} else if !strings.Contains(err.Error(), "control character") {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}
	// And an ordinary path still passes, or this refuses every install.
	opts := Options{
		AgentUser: "operator", ClientGroup: "shared", SecretsGroup: "store",
		BrokerUser: "br", KeeperUser: "kp", ExecUser: "ex", ConfigDir: "/opt/conf",
	}
	opts.applyDefaults()
	if _, err := opts.layout(); err != nil {
		t.Errorf("an ordinary config dir was refused: %v", err)
	}
}

// Each of these names is written into a file that is read a line at a time:
// config.toml, the logrotate rule, and the environment file pam_env hands a
// brokered command's sudo. A newline ends the line the name was written into
// and makes the rest of it a directive of its own, in files that decide what
// root is given. The account has to exist for an install to get this far, so
// this is the gate rather than the only thing standing in the way.
func TestAnAccountNameCarryingAControlCharacterIsRefused(t *testing.T) {
	for _, c := range []struct {
		field string
		set   func(*Options, string)
	}{
		{"agent user", func(o *Options, v string) { o.AgentUser = v }},
		{"client group", func(o *Options, v string) { o.ClientGroup = v }},
		{"secrets group", func(o *Options, v string) { o.SecretsGroup = v }},
		{"broker user", func(o *Options, v string) { o.BrokerUser = v }},
		{"keeper user", func(o *Options, v string) { o.KeeperUser = v }},
		{"exec user", func(o *Options, v string) { o.ExecUser = v }},
	} {
		for _, bad := range []string{"x\nroot ALL=(ALL) NOPASSWD: ALL", "x\ry", "x\x1bcy"} {
			opts := Options{AgentUser: "op", ConfigDir: "/etc/faramir"}
			c.set(&opts, bad)
			opts.applyDefaults()
			if _, err := opts.layout(); err == nil {
				t.Errorf("%s %q was accepted, so it renders into a generated file whole",
					c.field, bad)
			}
		}
	}
}

// And the ordinary names still render, or an install cannot be performed at all.
func TestOrdinaryAccountNamesStillRender(t *testing.T) {
	opts := Options{
		AgentUser: "op", ConfigDir: "/etc/faramir",
		ClientGroup: "faramir-client", SecretsGroup: "faramir-keeper",
		BrokerUser: "faramir-broker", KeeperUser: "faramir-keeper",
		ExecUser: "faramir-exec",
	}
	opts.applyDefaults()
	if _, err := opts.layout(); err != nil {
		t.Errorf("an ordinary install was refused: %v", err)
	}
}

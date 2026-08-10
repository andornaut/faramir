package install

import (
	"path/filepath"
	"strings"
	"testing"
)

// The key follows the config directory, so an encrypted home holding the
// secrets directory holds the key too and a powered-off disk carries neither.
func TestAgeKeyFollowsTheConfigDir(t *testing.T) {
	for _, tc := range []struct{ name, configDir, wantKey, wantDir string }{
		{"the default", DefaultConfigDir, DefaultConfigDir + "/age.key", DefaultConfigDir},
		{"an operator's home", "/home/op/.config/faramir", "/home/op/.config/faramir/age.key", "/home/op/.config/faramir"},
		{"a trailing slash is cleaned", "/srv/f/", "/srv/f/age.key", "/srv/f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				OperatorUser: "op", ClientGroup: DefaultClientGroup,
				BrokerUser: DefaultBrokerUser, KeeperUser: DefaultKeeperUser,
				ExecUser:  DefaultExecUser,
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
		{"the default", "", "", DefaultKeeperUser},
		{"a renamed keeper takes its group with it", "vault", "", "vault"},
		{"an explicit group is honoured", "", "faramir-secrets", "faramir-secrets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				OperatorUser: "op", KeeperUser: tc.keeperUser, SecretsGroup: tc.storeGroup,
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
// secrets directory stays nothing but ciphertext: [secrets] files globs it and
// filepath.Glob matches dotfiles.
func TestSopsConfigSitsAboveTheStore(t *testing.T) {
	layout := Layout{ConfigDir: "/etc/faramir"}
	if got, want := layout.SopsConfigPath(), "/etc/faramir/.sops.yaml"; got != want {
		t.Errorf("SopsConfigPath = %q, want %q", got, want)
	}
	if dir := filepath.Dir(layout.SopsConfigPath()); dir != layout.ConfigDir {
		t.Errorf("rule file is in %q, not the config directory %q", dir, layout.ConfigDir)
	}
	if filepath.Dir(layout.SopsConfigPath()) == layout.SecretsDir() {
		t.Error("the rule file is in the secrets directory, where the [secrets] glob reaches it")
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
	opts := Options{OperatorUser: "op"}
	opts.applyDefaults()
	if opts.SecretsGroup == opts.ClientGroup {
		t.Errorf("secrets group and client group are both %q", opts.ClientGroup)
	}
}

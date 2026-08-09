package install

import (
	"path/filepath"
	"strings"
	"testing"
)

// The key follows the config directory rather than sitting at a fixed path.
// That is what puts it inside an encrypted home when the store is already
// there, so a powered-off disk carries neither the ciphertext nor the key that
// opens it.
func TestAgeKeyFollowsTheConfigDir(t *testing.T) {
	for _, tc := range []struct{ name, configDir, wantKey, wantDir string }{
		{"the default", DefaultConfigDir, DefaultConfigDir + "/age.key", DefaultConfigDir},
		{"an operator's home", "/home/op/.faramir", "/home/op/.faramir/age.key", "/home/op/.faramir"},
		{"a trailing slash is cleaned", "/srv/f/", "/srv/f/age.key", "/srv/f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				Operator: "op", Group: DefaultGroup,
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
			// The directory is the config directory, which is created for the
			// config anyway, so nothing has to make one for the key.
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

// The store group is the keeper's own, so the set of accounts that can read the
// ciphertext is the one account that decrypts it, without a membership list to
// keep accurate.  A default that named a group of its own would be one more
// thing that can be right in the units and wrong in /etc/group.
func TestStoreGroupDefaultsToTheKeepersOwn(t *testing.T) {
	for _, tc := range []struct{ name, keeperUser, storeGroup, want string }{
		{"the default", "", "", DefaultKeeperUser},
		{"a renamed keeper takes its group with it", "vault", "", "vault"},
		{"an explicit group is honoured", "", "faramir-secrets", "faramir-secrets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				Operator: "op", KeeperUser: tc.keeperUser, StoreGroup: tc.storeGroup,
			}
			opts.applyDefaults()
			if opts.StoreGroup != tc.want {
				t.Errorf("StoreGroup = %q, want %q", opts.StoreGroup, tc.want)
			}
		})
	}
}

// The creation rule sits in the config directory, not in the store.
//
// sops walks up from the working directory, so the config directory is found
// from the store as well as from itself, and the store stays a directory
// holding nothing but ciphertext.  That second half is load bearing: [secrets]
// files globs the store and filepath.Glob matches dotfiles, so a rule file in
// there is swept up by a glob spelt .sops.yaml and fails to load as a managed
// file.
func TestSopsConfigSitsAboveTheStore(t *testing.T) {
	layout := Layout{ConfigDir: "/etc/faramir"}
	if got, want := layout.SopsConfigPath(), "/etc/faramir/.sops.yaml"; got != want {
		t.Errorf("SopsConfigPath = %q, want %q", got, want)
	}
	if dir := filepath.Dir(layout.SopsConfigPath()); dir != layout.ConfigDir {
		t.Errorf("rule file is in %q, not the config directory %q", dir, layout.ConfigDir)
	}
	if filepath.Dir(layout.SopsConfigPath()) == layout.SecretsDir() {
		t.Error("the rule file is in the store, where the [secrets] glob reaches it")
	}
	// The upward search reaches it from the store, which is the other half of
	// why it can live outside one.
	if !strings.HasPrefix(layout.SecretsDir(), layout.ConfigDir+string(filepath.Separator)) {
		t.Errorf("store %q is not under the config directory %q, so the upward "+
			"search would not reach the rule", layout.SecretsDir(), layout.ConfigDir)
	}
	// Named so doctor can report a copy an earlier layout left behind, which
	// would shadow this one for anything run from the store.
	if got, want := layout.StaleSopsConfigPath(), "/etc/faramir/secrets/.sops.yaml"; got != want {
		t.Errorf("StaleSopsConfigPath = %q, want %q", got, want)
	}
}

// The store group is never the group that admits a caller to the broker socket.
// Asking for a value by name and reading the file it comes from are different
// privileges, and the agent runs as an account holding the first.
func TestStoreGroupIsNotTheClientGroup(t *testing.T) {
	opts := Options{Operator: "op"}
	opts.applyDefaults()
	if opts.StoreGroup == opts.Group {
		t.Errorf("store group and client group are both %q", opts.Group)
	}
}

package install

import "testing"

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
				ConfigDir: tc.configDir, SecretsDir: tc.configDir + "/secrets",
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

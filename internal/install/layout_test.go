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

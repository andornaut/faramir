package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// testLayout moves everything off its default, so a literal left in a template
// shows up in the output.
func testLayout() Layout {
	opts := Options{
		AgentUser:    "operator",
		ClientGroup:  "shared",
		SecretsGroup: "store",
		BrokerUser:   "br",
		KeeperUser:   "kp",
		ExecUser:     "ex",
		ConfigDir:    "/opt/conf",
	}
	opts.applyDefaults()
	layout, err := opts.layout()
	if err != nil {
		panic(err)
	}
	// Each service account's group, named differently from the account. layout()
	// defaults each pair to the same string and stepAccounts resolves the real one
	// before the units render, so a directive taking a group from the *User* field
	// passes on this host and names the wrong group on one where an adopted
	// account's primary group is called something else.
	layout.ExecGroup = "exgrp"
	layout.BrokerGroup = "brgrp"
	layout.KeeperGroup = "kpgrp"
	return layout
}

// Catches a field renamed in Layout and not in the file that names it.
func TestTemplatesRender(t *testing.T) {
	layout := testLayout()
	assets := append([]string{
		"etc/config.toml.tmpl",
		"etc/logrotate.conf.tmpl",
		"etc/sudoers.tmpl",
		"etc/pam.d.tmpl",
		"etc/pam.d-sudo.tmpl",
		"agent/hooks/pam-approve.tmpl",
		"systemd/faramir.tmpfiles.conf.tmpl",
	}, unitValues()...)
	for _, asset := range assets {
		if _, err := render(asset, layout); err != nil {
			t.Errorf("%s: %v", asset, err)
		}
	}
}

func unitValues() []string {
	names := unitNames()
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, units[name])
	}
	return out
}

// supplementaryGroups is a rendered unit's SupplementaryGroups=, or "". Parsed
// rather than grepped: a unit that joins no group says so in a comment naming
// one.
func supplementaryGroups(t *testing.T, unit string, layout Layout) string {
	t.Helper()
	body, err := render(units[unit], layout)
	if err != nil {
		t.Fatal(err)
	}
	const directive = "SupplementaryGroups="
	for line := range strings.SplitSeq(string(body), "\n") {
		if after, found := strings.CutPrefix(line, directive); found {
			return after
		}
	}
	return ""
}

// Two groups with two jobs: the client group in the config the sockets check
// and the unit that reaches the working tree, the secrets group on the one
// daemon that opens the ciphertext. Disagreeing on the first refuses every
// connection; confusing the two hands the file to everyone who can ask for its
// value.
func TestGroupAgreesAcrossConfigAndUnits(t *testing.T) {
	layout := testLayout()
	config, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "\nallowed_group = \"shared\"\n") {
		t.Errorf("config does not admit group %q", layout.ClientGroup)
	}
	// The executor reaches the working tree, so the client group and only that: a
	// brokered command runs as it.
	if got := supplementaryGroups(t, "faramir-exec.service", layout); got != layout.ClientGroup {
		t.Errorf("exec joins %q, want the client group %q", got, layout.ClientGroup)
	}
	// The keeper decrypts and fingerprints, so the secrets group and not the
	// client group.
	if got := supplementaryGroups(t, "faramir-keeper.service", layout); got != layout.SecretsGroup {
		t.Errorf("keeper joins %q, want the secrets group %q", got, layout.SecretsGroup)
	}
	// The broker joins the executor's group to chown the ssh-agent socket, and
	// nothing else: it holds every decrypted value already, so read on the
	// ciphertext would only add files it never decrypts. Its group, not its
	// name: the two differ wherever an adopted account's primary group is called
	// something else.
	if got := supplementaryGroups(t, "faramir-broker.service", layout); got != layout.ExecGroup {
		t.Errorf("broker joins %q, want the executor's group %q alone",
			got, layout.ExecGroup)
	}
	socket, err := render(units["faramir-broker.socket"], layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(socket), "SocketGroup=shared") {
		t.Errorf("broker socket does not belong to group %q", layout.ClientGroup)
	}
}

// Every directive naming an account or the config carries the layout's value; a
// default left in one is a daemon running as a uid nothing created. Checked
// per directive, the units referring to each other by unit name in Requires=
// and After=.
//
// ExecStart too: one binary serves all three roles, so its argument is the only
// thing that says which a unit starts. SyslogIdentifier with it, systemd
// deriving that from the executable's name.
func TestAccountDirectivesUseTheLayout(t *testing.T) {
	layout := testLayout()
	for _, tc := range []struct {
		unit       string
		directives map[string]string
	}{
		{"faramir-broker.service", map[string]string{
			"User": "br", "Group": "brgrp", "StateDirectory": "br",
			// The executor's group and nothing else: the broker holds the plaintext and
			// asks the keeper what changed. "exgrp" rather than "ex", the account's
			// group not being assumed to share its name.
			"SupplementaryGroups": "exgrp",
			"Environment":         "FARAMIR_CONFIG=/opt/conf/config.toml",
			"ExecStart":           DefaultBinDir + "/faramir broker",
			"SyslogIdentifier":    "faramir-broker",
		}},
		{"faramir-keeper.service", map[string]string{
			"User": "kp", "Group": "kpgrp", "StateDirectory": "kp",
			"SupplementaryGroups": "store",
			"Environment":         "FARAMIR_CONFIG=/opt/conf/config.toml",
			"ExecStart":           DefaultBinDir + "/faramir keeper",
			"SyslogIdentifier":    "faramir-keeper",
		}},
		{"faramir-exec.service", map[string]string{
			// Group is the account's own, which is not assumed to be called what the
			// account is. StateDirectory is a directory name, so it stays the account's.
			"User": "ex", "Group": "exgrp", "StateDirectory": "ex",
			"SupplementaryGroups": "shared",
			"Environment":         "FARAMIR_CONFIG=/opt/conf/config.toml",
			"ExecStart":           DefaultBinDir + "/faramir exec",
			"SyslogIdentifier":    "faramir-exec",
		}},
		{"faramir-broker.socket", map[string]string{"SocketGroup": "shared"}},
		// The broker's group: these two admit the broker and nothing else, so a
		// name that resolved elsewhere would leave it unable to reach them.
		{"faramir-keeper.socket", map[string]string{"SocketGroup": "brgrp"}},
		{"faramir-exec.socket", map[string]string{"SocketGroup": "brgrp"}},
	} {
		body, err := render(units[tc.unit], layout)
		if err != nil {
			t.Fatal(err)
		}
		for directive, value := range tc.directives {
			if !strings.Contains(string(body), directive+"="+value+"\n") {
				t.Errorf("%s: want %s=%s", tc.unit, directive, value)
			}
		}
	}

	config, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"\nallowed_group = \"shared\"\n",
		"\nallowed_user = \"br\"\n",
		"\nexec_group = \"exgrp\"\n",
	} {
		if !strings.Contains(string(config), want) {
			t.Errorf("config: want %s", want)
		}
	}

	tmpfiles, err := render("systemd/faramir.tmpfiles.conf.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tmpfiles), "d /run/faramir 0755 br brgrp -") {
		t.Error("tmpfiles does not give the run directory to the broker's account")
	}
}

// One source and one name: the keeper reads $CREDENTIALS_DIRECTORY/age_key and
// never learns where systemd got it.
func TestKeeperCredentialSource(t *testing.T) {
	layout := testLayout()
	unit, err := render(units["faramir-keeper.service"], layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "LoadCredential=age_key:"+layout.AgeKeyPath) {
		t.Error("the keeper does not load the age key")
	}
	// Two entries claiming one credential name is a unit systemd refuses to start.
	if strings.Contains(string(unit), "LoadCredentialEncrypted=") {
		t.Error("the keeper loads an encrypted credential as well")
	}
}

// The keeper runs with the homes taken away, so a config directory in one is
// absent rather than unreadable unless it is bound back. One bind covers the
// store and the key too.
func TestTheKeeperUnitBindsOnlyWhatTheConfigDirNeeds(t *testing.T) {
	tests := []struct {
		name      string
		configDir string
		want      []string
	}{
		{
			name:      "outside every home",
			configDir: "/etc/faramir",
			want:      nil,
		},
		{
			name:      "in the agent account's home",
			configDir: "/home/operator/.config/faramir",
			want:      []string{"/home/operator/.config/faramir"},
		},
		{
			name:      "in root's home",
			configDir: "/root/.config/faramir",
			want:      []string{"/root/.config/faramir"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout := Layout{ConfigDir: test.configDir}
			got := layout.KeeperBinds()
			if len(got) != len(test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
			for i := range got {
				if got[i] != test.want[i] {
					t.Fatalf("got %v, want %v", got, test.want)
				}
			}
		})
	}
}

// Relaxing ProtectHome when nothing needs it would give the uid holding the age
// key a view of every home.
func TestKeeperProtectHome(t *testing.T) {
	strict := testLayout()
	strict.ConfigDir = "/etc/faramir"
	body, err := render(units["faramir-keeper.service"], strict)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "ProtectHome=true") {
		t.Error("keeper does not hide the homes when nothing needs them")
	}
	if strings.Contains(string(body), "BindReadOnlyPaths=") {
		t.Error("keeper binds a path back for no reason")
	}

	inHome := strict
	inHome.ConfigDir = "/home/operator/.config/faramir"
	body, err = render(units["faramir-keeper.service"], inHome)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "ProtectHome=tmpfs") {
		t.Error("keeper does not relax ProtectHome for a config directory in a home")
	}
	if !strings.Contains(string(body), "BindReadOnlyPaths=/home/operator/.config/faramir") {
		t.Error("keeper does not bind the config directory back")
	}
}

func TestLayoutValidation(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{
			name: "relative config dir",
			opts: Options{ConfigDir: "faramir"},
			want: "absolute",
		},
		{
			name: "config dir systemd would word-split",
			opts: Options{ConfigDir: "/etc/far amir"},
			want: "whitespace",
		},
		{
			name: "config dir systemd would expand",
			opts: Options{ConfigDir: "/etc/%faramir"},
			want: "'%'",
		},
		{
			name: "two service accounts sharing a uid",
			opts: Options{ConfigDir: "/etc/faramir", ExecUser: "faramir-broker"},
			want: "boundary",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.opts.applyDefaults()
			_, err := test.opts.layout()
			if err == nil {
				t.Fatal("accepted a layout that does not work")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error %q does not mention %q", err, test.want)
			}
		})
	}
}

// The SSH key renders into the base config. A key minted and absent from the
// file leaves the broker with an agent holding nothing.
func TestTheSSHKeyRendersIntoTheConfig(t *testing.T) {
	layout := testLayout()
	layout.SSHKey = "/var/lib/br/.ssh/identity"
	config, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if want := "\nkey = \"/var/lib/br/.ssh/identity\"\n"; !strings.Contains(string(config), want) {
		t.Errorf("config does not carry the key: want %s", want)
	}
}

// One is minted whether or not --ssh-key was passed, so a host always has a
// public half to put in an authorized_keys. Beside the age key: the key
// follows the config, so a config in an encrypted home has the private half in
// there too.
func TestTheSSHKeyDefaultsBesideTheAgeKey(t *testing.T) {
	opts := Options{
		AgentUser: "op", ClientGroup: DefaultClientGroup,
		BrokerUser: DefaultBrokerUser, KeeperUser: DefaultKeeperUser,
		ExecUser: DefaultExecUser, ConfigDir: "/home/op/.config/faramir",
	}
	layout, err := opts.layout()
	if err != nil {
		t.Fatal(err)
	}
	if want := "/home/op/.config/faramir/id_ed25519"; layout.SSHKey != want {
		t.Errorf("SSHKey = %q, want %q", layout.SSHKey, want)
	}
	if filepath.Dir(layout.SSHKey) != filepath.Dir(layout.AgeKeyPath) {
		t.Errorf("SSHKey %q is not beside the age key %q", layout.SSHKey, layout.AgeKeyPath)
	}
	// Named so that the deny patterns already refuse it by name, wherever a copy
	// turns up, and not only where ConfigDir was rendered into a rule.
	if filepath.Base(layout.SSHKey) != "id_ed25519" {
		t.Errorf("SSHKey is named %q; the deny patterns name id_ed25519",
			filepath.Base(layout.SSHKey))
	}
}

// The rendered base config has to load with the parser the daemons use: init
// writes it and then runs `broker --check`, so a key the parser does not know
// aborts an install that has already created accounts and written units.
func TestTheRenderedConfigLoads(t *testing.T) {
	body, err := render("etc/config.toml.tmpl", testLayout())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("the config init writes does not load: %v\n%s", err, body)
	}
}

// The rendered agent files are JSON, and Go's escape set is not JSON's.
//
// Every path in them is the operator's, from --config-dir or --ssh-key, and
// nothing on the way here refuses a control character in one. Rendered with
// Go's quoting, such a path produces a settings file the agent cannot parse:
// the enrolment reports success and every rule in that file is absent, which is
// the failure mode worth a test rather than the syntax error.
func TestTheRenderedAgentFilesAreParseableJSON(t *testing.T) {
	for _, awkward := range []string{
		"/etc/faramir",
		"/etc/far\amir",
		"/etc/far\vmir",
		"/etc/far\x01mir",
		"/etc/far\"mir",
		"/etc/far\\mir",
	} {
		t.Run(strconv.Quote(awkward), func(t *testing.T) {
			for _, tc := range []struct{ open, body, close string }{
				{"[", jsonLines("", []string{awkward}), "]"},
				{"{", jsonDenyMap("", []string{awkward}), "}"},
			} {
				var into any
				body := tc.open + strings.TrimSpace(tc.body) + tc.close
				if err := json.Unmarshal([]byte(body), &into); err != nil {
					t.Errorf("renders JSON nothing can parse: %v\n%s", err, body)
				}
			}
			// And the value survives rather than merely parsing.
			var got []string
			if err := json.Unmarshal([]byte("["+strings.TrimSpace(jsonLines("", []string{awkward}))+"]"), &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0] != awkward {
				t.Errorf("round trip = %q, want %q", got, awkward)
			}
		})
	}
}

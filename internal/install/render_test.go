package install

import (
	"strings"
	"testing"
)

// testLayout moves everything off its default, so a literal left in a template
// shows up in the output.
func testLayout() Layout {
	opts := Options{
		Operator:   "operator",
		Group:      "shared",
		StoreGroup: "store",
		BrokerUser: "br",
		KeeperUser: "kp",
		ExecUser:   "ex",
		ConfigDir:  "/opt/conf",
	}
	opts.applyDefaults()
	layout, err := opts.layout()
	if err != nil {
		panic(err)
	}
	return layout
}

// Catches a field renamed in Layout and not in the file that names it.
func TestTemplatesRender(t *testing.T) {
	layout := testLayout()
	assets := append([]string{
		"etc/config.toml.tmpl",
		"etc/logrotate.conf.tmpl",
		"systemd/faramir.tmpfiles.conf.tmpl",
	}, unitValues()...)
	for _, asset := range assets {
		if _, err := render(asset, layout); err != nil {
			t.Errorf("%s: %v", asset, err)
		}
	}
}

func unitValues() []string {
	var out []string
	for _, name := range unitNames() {
		out = append(out, units[name])
	}
	return out
}

// supplementaryGroups is a rendered unit's SupplementaryGroups=, or "".  Parsed
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
// and the unit that reaches the working tree, the store group on the one daemon
// that opens the ciphertext.  Disagreeing on the first refuses every connection;
// confusing the two hands the file to everyone who can ask for its value.
func TestGroupAgreesAcrossConfigAndUnits(t *testing.T) {
	layout := testLayout()
	config, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), `allowed_groups = ["shared"]`) {
		t.Errorf("config does not admit group %q", layout.Group)
	}
	// The executor reaches the working tree, so the client group and only that:
	// a brokered command runs as it.
	if got := supplementaryGroups(t, "faramir-exec.service", layout); got != layout.Group {
		t.Errorf("exec joins %q, want the client group %q", got, layout.Group)
	}
	// The keeper decrypts and fingerprints, so the store group and not the
	// client group.
	if got := supplementaryGroups(t, "faramir-keeper.service", layout); got != layout.StoreGroup {
		t.Errorf("keeper joins %q, want the store group %q", got, layout.StoreGroup)
	}
	// The broker joins the executor's group to chown the ssh-agent socket, and
	// nothing else: it holds every decrypted value already, so read on the
	// ciphertext would only add files it never decrypts.
	if got := supplementaryGroups(t, "faramir-broker.service", layout); got != layout.ExecUser {
		t.Errorf("broker joins %q, want the executor's group %q alone",
			got, layout.ExecUser)
	}
	socket, err := render(units["faramir-broker.socket"], layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(socket), "SocketGroup=shared") {
		t.Errorf("broker socket does not belong to group %q", layout.Group)
	}
}

// Every directive naming an account or the config carries the layout's value; a
// default left in one is a daemon running as a uid nothing created.  Checked per
// directive, the units referring to each other by unit name in Requires= and
// After=.
//
// ExecStart too: one binary serves all three roles, so its argument is the only
// thing that says which a unit starts.  SyslogIdentifier with it, systemd
// deriving that from the executable's name.
func TestAccountDirectivesUseTheLayout(t *testing.T) {
	layout := testLayout()
	want := map[string]map[string]string{
		"faramir-broker.service": {
			"User": "br", "Group": "br", "StateDirectory": "br",
			// The executor's group and nothing else: the broker holds the
			// plaintext and asks the keeper what changed.
			"SupplementaryGroups": "ex",
			"Environment":         "FARAMIR_CONFIG=/opt/conf/config.toml",
			"ExecStart":           DefaultBinDir + "/faramir broker",
			"SyslogIdentifier":    "faramir-broker",
		},
		"faramir-keeper.service": {
			"User": "kp", "Group": "kp", "StateDirectory": "kp",
			"SupplementaryGroups": "store",
			"Environment":         "FARAMIR_CONFIG=/opt/conf/config.toml",
			"ExecStart":           DefaultBinDir + "/faramir keeper",
			"SyslogIdentifier":    "faramir-keeper",
		},
		"faramir-exec.service": {
			"User": "ex", "Group": "ex", "StateDirectory": "ex",
			"SupplementaryGroups": "shared",
			"Environment":         "FARAMIR_CONFIG=/opt/conf/config.toml",
			"ExecStart":           DefaultBinDir + "/faramir exec",
			"SyslogIdentifier":    "faramir-exec",
		},
		"faramir-broker.socket": {"SocketGroup": "shared"},
		"faramir-keeper.socket": {"SocketGroup": "br"},
		"faramir-exec.socket":   {"SocketGroup": "br"},
	}
	for unit, directives := range want {
		body, err := render(units[unit], layout)
		if err != nil {
			t.Fatal(err)
		}
		for directive, value := range directives {
			if !strings.Contains(string(body), directive+"="+value+"\n") {
				t.Errorf("%s: want %s=%s", unit, directive, value)
			}
		}
	}

	config, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`allowed_groups = ["shared"]`,
		`allowed_users = ["br"]`,
		`exec_group = "ex"`,
	} {
		if !strings.Contains(string(config), want) {
			t.Errorf("config: want %s", want)
		}
	}

	tmpfiles, err := render("systemd/faramir.tmpfiles.conf.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tmpfiles), "d /run/faramir 0755 br br -") {
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
	// Two entries claiming one credential name is a unit systemd refuses to
	// start.
	if strings.Contains(string(unit), "LoadCredentialEncrypted=") {
		t.Error("the keeper loads an encrypted credential as well")
	}
}

// The keeper runs with the homes taken away, so a config directory in one is
// absent rather than unreadable unless it is bound back.  One bind covers the
// store and the key too.
func TestKeeperBinds(t *testing.T) {
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
			name:      "in the operator's home",
			configDir: "/home/operator/.faramir",
			want:      []string{"/home/operator/.faramir"},
		},
		{
			name:      "in root's home",
			configDir: "/root/.faramir",
			want:      []string{"/root/.faramir"},
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
	inHome.ConfigDir = "/home/operator/.faramir"
	body, err = render(units["faramir-keeper.service"], inHome)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "ProtectHome=tmpfs") {
		t.Error("keeper does not relax ProtectHome for a config directory in a home")
	}
	if !strings.Contains(string(body), "BindReadOnlyPaths=/home/operator/.faramir") {
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

// The SSH key renders into the base config.  A key named on the command line
// and absent from the file leaves the broker with an agent holding nothing.
func TestTheSSHKeyRendersIntoTheConfig(t *testing.T) {
	layout := testLayout()
	layout.SSHKey = "/var/lib/br/.ssh/identity"
	config, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if want := `keys = ["/var/lib/br/.ssh/identity"]`; !strings.Contains(string(config), want) {
		t.Errorf("config does not carry the key: want %s", want)
	}

	// Empty means empty, not a list holding an empty string.
	layout.SSHKey = ""
	config, err = render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "keys = []") {
		t.Error("no --ssh-key should leave keys empty")
	}
}

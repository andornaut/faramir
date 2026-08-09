package install

import (
	"strings"
	"testing"
)

// testLayout is a layout with everything moved off its default, so a literal
// left in a template shows up as the default leaking into the output.
func testLayout() Layout {
	opts := Options{
		Operator:   "operator",
		Group:      "shared",
		StoreGroup: "store",
		BrokerUser: "br",
		KeeperUser: "kp",
		ExecUser:   "ex",
		ConfigDir:  "/opt/conf",
		SecretsDir: "/opt/conf/store",
	}
	opts.applyDefaults()
	layout, err := opts.layout()
	if err != nil {
		panic(err)
	}
	return layout
}

// Every template renders, which is what catches a field renamed in Layout and
// not in the file that names it.
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

// Two groups with two jobs.  The client group is named in the config the
// sockets check and in the unit that reaches the working tree; the store group
// is named only by the daemons that read the ciphertext.  A rendered pair that
// disagrees on the first is a broker that installs cleanly and then refuses
// every connection.  A pair that confuses the two is worse: it hands everyone
// allowed to ask for a value by name the file that value came from.
func TestGroupAgreesAcrossConfigAndUnits(t *testing.T) {
	layout := testLayout()
	config, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), `allowed_groups = ["shared"]`) {
		t.Errorf("config does not admit group %q", layout.Group)
	}
	// The executor reaches the working tree, so it joins the client group.  It
	// must never join the store group: a brokered command runs as it, and that
	// is the account an agent's commands arrive on.
	exec, err := render(units["faramir-exec.service"], layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exec), "SupplementaryGroups=shared") {
		t.Errorf("exec does not join client group %q", layout.Group)
	}
	if strings.Contains(string(exec), layout.StoreGroup) {
		t.Errorf("exec names the store group %q; a brokered command runs as it",
			layout.StoreGroup)
	}
	// The keeper decrypts and the broker stats, so both need the store group and
	// neither needs the client group.
	for _, name := range []string{"faramir-keeper.service", "faramir-broker.service"} {
		body, err := render(units[name], layout)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "SupplementaryGroups=store") {
			t.Errorf("%s does not join store group %q", name, layout.StoreGroup)
		}
	}
	socket, err := render(units["faramir-broker.socket"], layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(socket), "SocketGroup=shared") {
		t.Errorf("broker socket does not belong to group %q", layout.Group)
	}
}

// Every directive that names an account or the config must carry the layout's
// value.  A default left in one of these is a daemon running as a uid the
// install never created, or reading a config nobody wrote.
//
// Checked per directive rather than by grepping the whole file: the units and
// the accounts are named independently of each other, and the units refer to
// each other by unit name in Requires= and After=.
//
// ExecStart is here for the same reason. One binary serves all three roles, so
// the argument is the only thing that says which one a unit starts, and a unit
// that starts the wrong role would come up healthy on the wrong socket.
// SyslogIdentifier with it: systemd derives it from the executable's name, which
// no longer differs between them.
func TestAccountDirectivesUseTheLayout(t *testing.T) {
	layout := testLayout()
	want := map[string]map[string]string{
		"faramir-broker.service": {
			"User": "br", "Group": "br", "StateDirectory": "br",
			"SupplementaryGroups": "store ex",
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

// One source for the age key, and one name for it: the keeper reads
// $CREDENTIALS_DIRECTORY/age_key and never learns where systemd got it.
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
	// start, which is what a second source would have to be.
	if strings.Contains(string(unit), "LoadCredentialEncrypted=") {
		t.Error("the keeper loads an encrypted credential as well")
	}
}

// The keeper runs with the homes taken away, so a config or store kept in one
// has to be bound back or it is not merely unreadable but absent.
func TestKeeperBinds(t *testing.T) {
	tests := []struct {
		name       string
		configDir  string
		secretsDir string
		want       []string
	}{
		{
			name:       "outside every home",
			configDir:  "/etc/faramir",
			secretsDir: "/etc/faramir/secrets",
			want:       nil,
		},
		{
			name:       "store nested in the config dir collapses to one bind",
			configDir:  "/home/operator/.faramir",
			secretsDir: "/home/operator/.faramir/secrets",
			want:       []string{"/home/operator/.faramir"},
		},
		{
			name:       "config outside, store in a home",
			configDir:  "/etc/faramir",
			secretsDir: "/home/operator/store",
			want:       []string{"-/home/operator/store"},
		},
		{
			name:       "both in a home, unrelated paths",
			configDir:  "/home/operator/.faramir",
			secretsDir: "/home/operator/store",
			want:       []string{"/home/operator/.faramir", "-/home/operator/store"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout := Layout{ConfigDir: test.configDir, SecretsDir: test.secretsDir}
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

// A store outside the homes leaves ProtectHome at its strictest.  Relaxing it
// when nothing needs it would hand the uid holding the age key a view of every
// home for no reason.
func TestKeeperProtectHome(t *testing.T) {
	strict := testLayout()
	strict.ConfigDir = "/etc/faramir"
	strict.SecretsDir = "/etc/faramir/secrets"
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
	inHome.SecretsDir = "/home/operator/.faramir/secrets"
	body, err = render(units["faramir-keeper.service"], inHome)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "ProtectHome=tmpfs") {
		t.Error("keeper does not relax ProtectHome for a store in a home")
	}
	if !strings.Contains(string(body), "BindReadOnlyPaths=/home/operator/.faramir") {
		t.Error("keeper does not bind the store back")
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
			name: "config dir under the private tmp",
			opts: Options{ConfigDir: "/tmp/faramir"},
			want: "PrivateTmp",
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

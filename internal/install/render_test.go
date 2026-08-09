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

// supplementaryGroups is the value of a rendered unit's SupplementaryGroups=,
// or "" when it has none.
//
// Parsed rather than grepped for, because every unit that does not join a group
// says so in a comment naming it, and a substring match cannot tell the
// directive from the explanation of why it is absent.
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

// Two groups with two jobs.  The client group is named in the config the
// sockets check and in the unit that reaches the working tree; the store group
// is named by the one daemon that opens the ciphertext.  A rendered pair that
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
	// The executor reaches the working tree, so it joins the client group and
	// only that.  It must never join the store group: a brokered command runs
	// as it, and that is the account an agent's commands arrive on.
	if got := supplementaryGroups(t, "faramir-exec.service", layout); got != layout.Group {
		t.Errorf("exec joins %q, want the client group %q", got, layout.Group)
	}
	// The keeper decrypts and fingerprints, so it is the one that needs the
	// store group, and it does not need the client group.
	if got := supplementaryGroups(t, "faramir-keeper.service", layout); got != layout.StoreGroup {
		t.Errorf("keeper joins %q, want the store group %q", got, layout.StoreGroup)
	}
	// The broker joins the executor's group to chown the ssh-agent socket, and
	// nothing else.  It already holds every decrypted value, so read on the
	// ciphertext would let it copy files it never decrypts and buy no capability
	// it lacks; it asks the keeper what changed instead.
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
			// The executor's group and nothing else.  Not the store group: the
			// broker holds the plaintext and asks the keeper what changed, so
			// read on the ciphertext would add reach without adding a capability.
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

// The keeper runs with the homes taken away, so a config directory kept in one
// has to be bound back or it is not merely unreadable but absent.  The store
// and the key are inside it, so one bind covers all three.
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

// A config directory outside the homes leaves ProtectHome at its strictest.
// Relaxing it when nothing needs it would hand the uid holding the age key a
// view of every home for no reason.
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

// The SSH key renders into the base config, which is what replaced the drop-in
// init used to write.  A key named on the command line and absent from the file
// leaves the broker with an agent holding nothing, and every brokered command
// unable to reach a managed host.
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

	// And empty means empty, rather than a list holding an empty string, which
	// is a path the broker would try to load.
	layout.SSHKey = ""
	config, err = render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "keys = []") {
		t.Error("no --ssh-key should leave keys empty")
	}
}

package broker

// The SSH key the broker is configured to lend.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/andornaut/faramir/internal/config"
)

// A configured but absent key leaves the broker up and unable to reach any host
// that expects it.
func TestCheckFailsOnAConfiguredSSHKeyThatIsMissing(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s.Config.Ssh.Key = filepath.Join(t.TempDir(), "absent_ed25519")

	body, code := s.CheckOutput()
	if code == 0 {
		t.Error("a missing SSH key passed the install gate")
	}
	var report struct {
		Ssh struct {
			Key struct {
				Path     string `json:"path"`
				Readable bool   `json:"readable"`
			} `json:"key"`
		} `json:"ssh"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Ssh.Key.Path != s.Config.Ssh.Key || report.Ssh.Key.Readable {
		t.Errorf("report does not name the unreadable key: %+v", report.Ssh.Key)
	}
}

// writeKeyPair writes an ed25519 private key, encrypted with passphrase when
// one is given, plus the matching .pub, and returns both paths.
func writeKeyPair(t *testing.T, passphrase string) (private, public string) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}

	private = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(private, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	public = private + ".pub"
	if err := os.WriteFile(public, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		t.Fatal(err)
	}
	return private, public
}

func TestCheckPassesOnAKeyTheBrokerCanUse(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	key, _ := writeKeyPair(t, "")
	s.Config.Ssh.Key = key

	if _, code := s.CheckOutput(); code != 0 {
		t.Error("a usable key failed the gate")
	}
}

// ssh-add cannot type a passphrase, so the broker comes up with an agent
// holding nothing. A readability check alone would call that healthy.
func TestCheckFailsOnAPassphraseProtectedKey(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	key, _ := writeKeyPair(t, "hunter2")
	s.Config.Ssh.Key = key

	body, code := s.CheckOutput()
	if code == 0 {
		t.Fatal("a key ssh-add will refuse passed the gate")
	}
	if !strings.Contains(string(body), "passphrase") {
		t.Errorf("the report does not say why:\n%s", body)
	}
}

// Naming the .pub is the other way to configure this wrong.
func TestCheckFailsWhenKeyNamesThePublicKey(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	_, pub := writeKeyPair(t, "")
	s.Config.Ssh.Key = pub

	body, code := s.CheckOutput()
	if code == 0 {
		t.Fatal("a public key passed the gate")
	}
	if !strings.Contains(string(body), "public key") {
		t.Errorf("the report does not say why:\n%s", body)
	}
}

// The report describes key material, so it must carry none.
func TestTheKeyReportContainsNoKeyMaterial(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	key, _ := writeKeyPair(t, "hunter2")
	s.Config.Ssh.Key = key

	data, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := s.CheckOutput()
	for line := range strings.SplitSeq(string(data), "\n") {
		if len(line) > 20 && strings.Contains(string(body), line) {
			t.Fatalf("the report quotes the key file: %q", line)
		}
	}
}

// A configured entry that named no file is reported and does not fail the
// audit: an unmounted store looks exactly like one never written, and a host
// that manages no credentials holds no value for output to carry. What the
// operator gets is the report, not a broker that stops.
func TestCheckPassesOnAConfiguredEntryThatNamedNoFile(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, file string }{
		{"a store that is not there", filepath.Join(t.TempDir(), "absent.sops.yml")},
		{"a store under something not a directory", filepath.Join(notADir, "v.sops.yml")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"}, tc.file)
			if _, code := s.CheckOutput(); code != 0 {
				t.Error("an entry that named no file failed the audit")
			}
		})
	}
}

// Unset is a deliberate configuration, not a fault.
func TestCheckPassesWhenNoSSHKeyIsConfigured(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s.Config.Ssh.Key = ""
	if _, code := s.CheckOutput(); code != 0 {
		t.Error("an unset [ssh] key failed the gate")
	}
}

// The keeper's socket is the age key by another route, and the executor's runs
// a command with no policy, redaction or audit record; each has one legitimate
// client.
func TestCheckFailsOnASocketOpenedToAnotherAccount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the broker cannot tell its own name from any other")
	}
	for _, tc := range []struct {
		name  string
		apply func(*testing.T, *config.Config)
	}{
		{"the keeper admits the executor", func(_ *testing.T, c *config.Config) {
			c.Keeper.AllowedUser = "root"
		}},
		{"the executor admits somebody else", func(_ *testing.T, c *config.Config) {
			c.Executor.AllowedUser = "root"
		}},
		// The bound socket, not a config key describing it: systemd's SocketMode= is
		// what the mode ends up as under activation.
		{"the broker socket is world-reachable", func(t *testing.T, c *config.Config) {
			t.Helper()
			ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", c.Server.SocketPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			if err := os.Chmod(c.Server.SocketPath, 0o666); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
			s.Config.Ssh.Key = ""
			tc.apply(t, s.Config)
			if _, code := s.CheckOutput(); code == 0 {
				t.Error("passed the gate")
			}
		})
	}
}

// The broker's own account is the one name that belongs in either.
func TestCheckPassesWhenTheSocketsNameTheBroker(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user to name")
	}
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s.Config.Ssh.Key = ""
	s.Config.Keeper.AllowedUser = me.Username
	s.Config.Executor.AllowedUser = me.Username
	if _, code := s.CheckOutput(); code != 0 {
		t.Error("a config naming only the broker failed the gate")
	}
}

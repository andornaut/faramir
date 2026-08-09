package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keepertest"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
)

// secretFiles has to be set here rather than on the returned server: the store
// takes a copy of the secrets config at construction, so assigning to
// s.Config.Secrets afterwards changes nothing the store reads.
func newServer(t *testing.T, values map[string]string, secretFiles ...string) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Path: "<test>",
		Server: config.ServerConfig{
			SocketPath: filepath.Join(dir, "broker.sock"), SocketMode: 0o660,
			MaxConcurrency: 2, MaxRequestBytes: 262144,
		},
		Keeper: config.KeeperConfig{SocketPath: keepertest.New(t, values, secretFiles...).Path},
		Exec: config.ExecConfig{
			DefaultTimeoutSec: 30, MaxTimeoutSec: 60,
			BaseEnv: map[string]string{"PATH": "/usr/bin:/bin"},
		},
		Secrets: config.SecretsConfig{
			Files:              secretFiles,
			RefreshIntervalSec: 0, MinLength: 8, MinUniqueChars: 4,
			MinEntropyBitsPerChar: 1.5,
		},
		Audit: config.AuditConfig{LogPath: filepath.Join(dir, "audit.log"), MaxRecordBytes: 1 << 20},
	}
	s := New(cfg)
	s.Store.Reload()
	return s
}

func output(t *testing.T, r protocol.Response) string {
	t.Helper()
	out, ok := r["output"].(string)
	if !ok {
		t.Fatalf("response has no string output: %v", r)
	}
	return out
}

// -- the request limit ------------------------------------------------------

// The one reply that is produced before a request is parsed, so nothing else in
// this file reaches it.
//
// It has to be its own code rather than a bad_request: `faramir redact` answers
// a too_large by passing the text through UNREDACTED and saying so, and chooses
// its chunk size to stay under this limit.  A reply that said something else
// would leave that fallback unreachable and the caller retrying a request that
// cannot get smaller.
func TestARequestOverTheLimitIsRefusedAsTooLarge(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s.Config.Server.MaxRequestBytes = 64
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })

	conn, err := net.Dial("unix", s.Config.Server.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	body := `{"op":"redact","text":"` + strings.Repeat("x", 200) + `"}` + "\n"
	if _, err := conn.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}

	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &out); err != nil {
		t.Fatalf("unmarshal %q: %v", line, err)
	}
	if out.Error == nil {
		t.Fatalf("an oversized request was accepted: %s", line)
	}
	if out.Error.Code != "too_large" {
		t.Errorf("code = %q, want too_large", out.Error.Code)
	}
	// The limit itself, because the caller's only remedy is to send less and it
	// has no other way to learn how much less.
	if !strings.Contains(out.Error.Message, "64") {
		t.Errorf("the message does not say what the limit is: %q", out.Error.Message)
	}
}

// -- the --check path -------------------------------------------------------

func TestCheckPrintsOneJSONObject(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	body, code := s.CheckOutput()
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("not one JSON object: %v\n%s", err, body)
	}
	if _, ok := out["secrets"]; !ok {
		t.Errorf("no secrets key: %s", body)
	}
	// The allowlist is gone; --check must not still claim to report rules.
	if _, ok := out["allow_rules"]; ok {
		t.Errorf("--check still reports allow_rules: %s", body)
	}
}

func TestCheckNamesTheRefusedRefsAndTheReason(t *testing.T) {
	s := newServer(t, map[string]string{"tiny": "abc"})
	body, _ := s.CheckOutput()
	if !strings.Contains(string(body), "tiny") {
		t.Errorf("the refused ref was not named: %s", body)
	}
	if !strings.Contains(string(body), "shorter than") {
		t.Errorf("the reason was not given: %s", body)
	}
}

// --check is the install gate: the config parses, but a command injecting that
// ref will fail at runtime, so it must not report success.
func TestCheckExitsNonZeroWhenARefWasRefused(t *testing.T) {
	s := newServer(t, map[string]string{"tiny": "abc"})
	if _, code := s.CheckOutput(); code == 0 {
		t.Error("--check succeeded with a refused ref")
	}
}

// -- agent-facing responses -------------------------------------------------

func TestListSecretsOmitsARefusedRef(t *testing.T) {
	s := newServer(t, map[string]string{
		"good": "hunter2-correct-horse", "tiny": "abc",
	})
	body := output(t, s.opListSecrets())
	if !strings.Contains(body, "secret://good") {
		t.Errorf("a loaded ref is missing: %q", body)
	}
	if strings.Contains(body, "tiny") {
		t.Errorf("a refused ref was listed: %q", body)
	}
}

func TestListSecretsEndsEveryLine(t *testing.T) {
	s := newServer(t, map[string]string{
		"a": "hunter2-correct-horse", "b": "another-good-value",
	})
	body := output(t, s.opListSecrets())
	if body == "" {
		t.Fatal("empty output")
	}
	if !strings.HasSuffix(body, "\n") {
		t.Errorf("the last line is unterminated: %q", body)
	}
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if !strings.HasPrefix(line, "secret://") {
			t.Errorf("unexpected line: %q", line)
		}
	}
}

func TestListSecretsIsEmptyWhenNothingLoaded(t *testing.T) {
	s := newServer(t, map[string]string{})
	if body := output(t, s.opListSecrets()); body != "" {
		t.Errorf("output = %q, want empty", body)
	}
}

// A value that is never tokenized is one worth targeting, so status must not
// name it, and must not carry the operator-only refusal list.
func TestStatusDoesNotNameARefusedRef(t *testing.T) {
	s := newServer(t, map[string]string{
		"good": "hunter2-correct-horse", "tiny": "abc",
	})
	body := output(t, s.opStatus())
	if strings.Contains(body, "tiny") {
		t.Errorf("status named a refused ref: %q", body)
	}
	if strings.Contains(body, "not_redactable") {
		t.Errorf("status carried the refusal list: %q", body)
	}
	if !strings.Contains(body, "count") {
		t.Errorf("status is missing count: %q", body)
	}
	// Both removed upstream; status must not still advertise them.
	for _, gone := range []string{"allow_rules", "sync_enabled"} {
		if strings.Contains(body, gone) {
			t.Errorf("status still reports %s: %q", gone, body)
		}
	}
}

func TestStatusNeverCarriesAValue(t *testing.T) {
	const secret = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"a/b": secret})
	if body := output(t, s.opStatus()); strings.Contains(body, secret) {
		t.Errorf("status leaked a value: %q", body)
	}
}

// An unexpected error string can have interpolated a secret, so it goes
// through the redactor like every other agent-visible string.
func TestSafeDetailRedactsAValue(t *testing.T) {
	const secret = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"a/b": secret})
	got := s.safeDetail("exec failed: could not connect with " + secret)
	if strings.Contains(got, secret) {
		t.Errorf("an error message leaked a value: %q", got)
	}
	if !strings.Contains(got, "«SECRET:a/b»") {
		t.Errorf("no token in %q", got)
	}
}

// -- the SSH keys the broker is configured to lend ---------------------------

// A key named in the config but absent is the other way an install comes up
// healthy and does nothing: the broker starts, every socket is active, and no
// brokered command can reach a host that expects that key.  --check is the
// install gate, so it has to fail on it.
func TestCheckFailsOnAConfiguredSSHKeyThatIsMissing(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s.Config.Ssh.Keys = []string{filepath.Join(t.TempDir(), "absent_ed25519")}

	body, code := s.CheckOutput()
	if code == 0 {
		t.Error("a missing SSH key passed the install gate")
	}
	var report struct {
		Ssh struct {
			Keys []struct {
				Path     string `json:"path"`
				Readable bool   `json:"readable"`
			} `json:"keys"`
		} `json:"ssh"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Ssh.Keys) != 1 || report.Ssh.Keys[0].Readable {
		t.Errorf("report does not name the unreadable key: %+v", report.Ssh.Keys)
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
	s.Config.Ssh.Keys = []string{key}

	if _, code := s.CheckOutput(); code != 0 {
		t.Error("a usable key failed the gate")
	}
}

// ssh-add cannot type a passphrase, so the broker comes up with an agent
// holding nothing: every socket active, every unit running, and no brokered
// command able to authenticate against a single managed host.  Checking only
// that the file is readable reports that install as healthy.
func TestCheckFailsOnAPassphraseProtectedKey(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	key, _ := writeKeyPair(t, "hunter2")
	s.Config.Ssh.Keys = []string{key}

	body, code := s.CheckOutput()
	if code == 0 {
		t.Fatal("a key ssh-add will refuse passed the gate")
	}
	if !strings.Contains(string(body), "passphrase") {
		t.Errorf("the report does not say why:\n%s", body)
	}
}

// Naming the .pub is the other way to configure this wrong, and it is just as
// readable as the private key it sits next to.
func TestCheckFailsWhenKeysNamesThePublicKey(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	_, pub := writeKeyPair(t, "")
	s.Config.Ssh.Keys = []string{pub}

	body, code := s.CheckOutput()
	if code == 0 {
		t.Fatal("a public key passed the gate")
	}
	if !strings.Contains(string(body), "public key") {
		t.Errorf("the report does not say why:\n%s", body)
	}
}

// The report is operator-facing and describes key material, so it must carry
// none of it.
func TestTheKeyReportContainsNoKeyMaterial(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	key, _ := writeKeyPair(t, "hunter2")
	s.Config.Ssh.Keys = []string{key}

	data, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := s.CheckOutput()
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > 20 && strings.Contains(string(body), line) {
			t.Fatalf("the report quotes the key file: %q", line)
		}
	}
}

// A configured file that is not there fails the gate.  The store can sit on a
// filesystem that is not mounted yet, which looks exactly like one that was
// never written, so the gate has to refuse both: passing means the broker came
// up redacting nothing and said it was healthy.
func TestCheckFailsOnASecretsFileThatIsNotThere(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"},
		filepath.Join(t.TempDir(), "absent.sops.yml"))

	if _, code := s.CheckOutput(); code == 0 {
		t.Error("a store that is not there passed the gate")
	}
}

// A file that exists and did not load leaves the broker serving fewer values
// than it is configured for, and every value it did not load is one that
// reaches the agent in plaintext.  Reporting that as a healthy install is the
// failure mode the gate exists to prevent.
func TestCheckFailsOnASecretsFileThatCouldNotBeRead(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"},
		filepath.Join(notADir, "v.sops.yml"))

	if _, code := s.CheckOutput(); code == 0 {
		t.Error("a secrets file that could not be read passed the gate")
	}
}

// Empty is a deliberate configuration, not a fault.
func TestCheckPassesWhenNoSSHKeysAreConfigured(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s.Config.Ssh.Keys = nil
	if _, code := s.CheckOutput(); code != 0 {
		t.Error("an empty [ssh] keys failed the gate")
	}
}

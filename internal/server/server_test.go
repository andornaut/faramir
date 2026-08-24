package server

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
	"github.com/andornaut/faramir/internal/keepertest"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/secretlink"
	"github.com/andornaut/faramir/internal/secretstore"
	"github.com/andornaut/faramir/internal/sockutil"
)

// managedFile is a file for the managed store to name, so the store reports one
// as present. Contents are the keeper double's business, not this file's.
func managedFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed.sops.yml")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// secretFiles is set here because the store copies the secrets config at
// construction, so a later assignment to s.Config.Secret reads nothing.
// newServer is a healthy install: one managed file, present and read, which is
// what the exec and redact gate asks for. A test that wants the store
// unconfigured calls newUnconfiguredServer.
func newServer(t *testing.T, values map[string]string, secretFiles ...string) *Server {
	t.Helper()
	if len(secretFiles) == 0 {
		secretFiles = []string{managedFile(t)}
	}
	return serverWith(t, keepertest.New(t, values, secretFiles...), secretFiles...)
}

// newUnconfiguredServer names no managed store, which is a broker holding an
// empty value set: it serves, there being no managed value for output to carry.
func newUnconfiguredServer(t *testing.T, values map[string]string) *Server {
	t.Helper()
	return serverWith(t, keepertest.New(t, values))
}

// newUnreadableServer is the state that does refuse: a managed file that was
// found and did not load, where the broker knows values exist and cannot cover
// them.
func newUnreadableServer(t *testing.T) *Server {
	t.Helper()
	file := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"}, file)
	k.SetErrors([]string{file + ": could not decrypt"})
	s := serverWith(t, k, file)
	s.Store.Reload()
	if s.Store.Unreadable() == "" {
		t.Fatal("the fixture does not refuse: a file that did not load should")
	}
	return s
}

// serverWith is newServer against a keeper the caller already has, for a test
// that has to reach into it.
func serverWith(t *testing.T, k *keepertest.Keeper, secretFiles ...string) *Server {
	t.Helper()
	// No staleness gate: these tests drive the store by hand, and the interval
	// is a constant in the binary rather than a key this config could set.
	wasInterval := config.MinRefreshSec
	config.MinRefreshSec = 0
	t.Cleanup(func() { config.MinRefreshSec = wasInterval })
	dir := t.TempDir()
	cfg := &config.Config{
		Path: "<test>",
		Server: config.ServerConfig{
			SocketPath: filepath.Join(dir, "broker.sock")},
		Keeper: config.KeeperConfig{SocketPath: k.Path},
		Command: config.CommandConfig{
			TimeoutSec: 30, MaxTimeoutSec: 60, Concurrency: 10,
			Env: map[string]string{"PATH": "/usr/bin:/bin"},
		},
		Secret: config.SecretConfig{Patterns: secretFiles, MinLength: 8},
		Audit:  config.AuditConfig{LogPath: filepath.Join(dir, "audit.log")},
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

// Produced before a request is parsed, so it has its own code rather than being
// a bad_request: an oversized request is a client that needs to send less, not
// one that sent nonsense. `faramir redact` withholds the text either way, as it
// does for every other error -- text that reached no redactor is text nobody
// checked -- and the code is what tells the two apart in the audit and to
// whoever is reading the failure.
func TestARequestOverTheLimitIsRefusedAsTooLarge(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	// Restored, this being a package variable rather than a field on the server:
	// left at 64 it is every later test's limit too, and the ones that send a
	// stream are refused as too_large.
	was := config.MaxRequestBytes
	config.MaxRequestBytes = 64
	t.Cleanup(func() { config.MaxRequestBytes = was })
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", s.Config.Server.SocketPath)
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
	// The limit itself: the caller's only remedy is to send less.
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

// The config parses, but a command injecting that ref fails at runtime.
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
	if !strings.Contains(body, "faramir://good") {
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
	for line := range strings.SplitSeq(strings.TrimSuffix(body, "\n"), "\n") {
		if !strings.HasPrefix(line, "faramir://") {
			t.Errorf("unexpected line: %q", line)
		}
	}
}

func TestListSecretsIsEmptyWhenNothingLoaded(t *testing.T) {
	s := newUnconfiguredServer(t, map[string]string{})
	if body := output(t, s.opListSecrets()); body != "" {
		t.Errorf("output = %q, want empty", body)
	}
}

// A value that is never tokenized is worth targeting, so status names neither
// it nor the operator-only refusal list.
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
	// It says a ref like that exists, which is what the exit status already
	// says: without it, status exits 1 and nothing anywhere gives a reason.
	// Counted, so what it adds is the number and not the name.
	if !strings.Contains(body, "cannot be redacted") {
		t.Errorf("status gives no reason for the status it exits with: %q", body)
	}
}

// The field that carries that reason: every state that leaves a configured ref
// not working or a configured value uncovered, counted. A caller reading it
// knows what is wrong and how much of it; `doctor` is where each is named.
func TestStatusSaysWhyItIsDegradedWithoutNamingARef(t *testing.T) {
	s := newServer(t, map[string]string{
		"good": "hunter2-correct-horse", "tiny": "abc",
	})
	var body struct {
		Degraded string `json:"degraded"`
	}
	if err := json.Unmarshal([]byte(output(t, s.opStatus())), &body); err != nil {
		t.Fatal(err)
	}
	if body.Degraded == "" {
		t.Fatal("a degraded store reports no reason")
	}
	for _, ref := range []string{"tiny", "good"} {
		if strings.Contains(body.Degraded, ref) {
			t.Errorf("the reason names %q: %s", ref, body.Degraded)
		}
	}
	if !strings.Contains(body.Degraded, "doctor") {
		t.Errorf("the reason does not say where the refs are named: %s", body.Degraded)
	}
	// And a store doing its whole job says nothing, so the field is a reason or
	// it is empty, never a sentence about being fine.
	healthy := newServer(t, map[string]string{"good": "hunter2-correct-horse"})
	if err := json.Unmarshal([]byte(output(t, healthy.opStatus())), &body); err != nil {
		t.Fatal(err)
	}
	if body.Degraded != "" {
		t.Errorf("a healthy store reports %q", body.Degraded)
	}
}

// One file is loaded, so status names it rather than reporting a list of one.
// The client reconstructs the config directory from this, so an install whose
// config was moved is found by what the broker answers rather than by the
// compiled-in default.
func TestStatusNamesTheOneConfigItLoaded(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	var body struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal([]byte(output(t, s.opStatus())), &body); err != nil {
		t.Fatalf("status is not JSON: %v", err)
	}
	if body.Config != s.Config.Path {
		t.Errorf("config = %q, want the loaded file %q", body.Config, s.Config.Path)
	}
}

// A link that did not load refuses one ref and leaves the broker serving, so
// nothing about a command's own failure says the host is degraded. The exit
// code is what carries it, and the body still prints.
func TestStatusExitsNonZeroOnADegradedLink(t *testing.T) {
	managed := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"}, managed)
	s := serverWith(t, k, managed)
	s.Config.Secret.Links = []config.Link{{
		Ref: "npm/token", Path: filepath.Join(t.TempDir(), "gone"),
		Type: secretlink.KindText,
	}}
	s.Store = secretstore.New(s.Config.Secret, s.Config.Keeper)
	s.Store.Reload()

	response := s.opStatus()
	if code, _ := response["exit_code"].(int); code == 0 {
		t.Error("status exited 0 with a link that did not load")
	}
	body := output(t, response)
	if !strings.Contains(body, "npm/token") {
		t.Errorf("status does not name the degraded ref: %q", body)
	}
	// The path is the location of a credential, and this answer reaches the
	// agent. DescribeForOperator is what carries it.
	if strings.Contains(body, "gone") {
		t.Errorf("status carries the linked file's path: %q", body)
	}
	// Serving, not refusing: every other ref is unaffected.
	if reason := s.Store.Unreadable(); reason != "" {
		t.Errorf("a degraded link stopped the broker: %s", reason)
	}
}

func TestStatusNeverCarriesAValue(t *testing.T) {
	const secret = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"a/b": secret})
	if body := output(t, s.opStatus()); strings.Contains(body, secret) {
		t.Errorf("status leaked a value: %q", body)
	}
}

// An unexpected error string may have interpolated a value.
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

// -- the SSH key the broker is configured to lend ----------------------------

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

// -- an empty value set ------------------------------------------------------

// Holding nothing is not holding less than it should: there is no managed value
// for output to carry that the redactor lacks, so the ops run. A host that
// manages no credentials is every install on its first day, and refusing there
// stopped work to protect nothing.
func TestExecAndRedactAreServedWhileTheValueSetIsEmpty(t *testing.T) {
	s := newUnconfiguredServer(t, map[string]string{})
	peer := &sockutil.Peer{UID: 1000}

	// redact answers in full: it needs nothing but the redactor.
	if got := handle(s, map[string]any{"op": "redact", "text": "anything"}, peer); got["error"] != nil {
		t.Errorf("redact was refused with an empty value set: %v", got["error"])
	}
	// run reaches the executor, which this fixture does not have, so what is
	// asserted is that it got past the gate rather than that it ran.
	got := handle(s, map[string]any{"op": "run", "cmd": []any{"true"}, "cwd": t.TempDir()}, peer)
	if failure, ok := got["error"].(map[string]string); ok && failure["code"] == "no_secrets" {
		t.Errorf("run was refused for an empty value set: %v", failure)
	}
	// Served, and said: the one case this cannot tell from a host that manages
	// nothing is a store on a filesystem that is not mounted.
	if s.Store.EmptySet() == "" {
		t.Error("EmptySet said nothing about a broker holding no values")
	}
}

// A file that did not load leaves a set that is short rather than empty, so a
// value-count check would serve it: the values that did load cover their own
// output and the rest is missing with nothing to say so.
func TestExecIsRefusedWhenOneFileDidNotLoad(t *testing.T) {
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
	file := managedFile(t)
	k.SetFiles([]string{file})
	k.SetErrors([]string{"/etc/faramir/secrets/other.sops.yml: could not decrypt"})
	s := serverWith(t, k, file)
	s.Store.Reload()
	if s.Store.Count() == 0 {
		t.Fatal("this case is only interesting while some values did load")
	}

	got := handle(s, map[string]any{
		"op": "run", "cmd": []any{"true"}, "cwd": t.TempDir(),
	}, &sockutil.Peer{UID: 1000})
	failure, ok := got["error"].(map[string]string)
	if !ok || failure["code"] != "no_secrets" {
		t.Errorf("a short value set was served: %v", got)
	}
}

// The set kept when the keeper cannot be reached is the last one known to be
// true, so it is unconfirmed rather than short, and the store stays servable:
// refusing on it would turn a keeper hiccup into refused commands. What the
// gate does with that answer is TestExecAndRedactAreRefusedWhileNoManagedFileWasRead.
func TestTheStoreStaysServableWhileTheKeeperIsUnreachable(t *testing.T) {
	file := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"}, file)
	s := serverWith(t, k, file)
	s.Store.Reload()
	_ = k.Listener.Close()
	s.Store.Reload()

	if len(s.Store.LoadErrors()) == 0 {
		t.Fatal("closing the keeper did not produce a load error")
	}
	if reason := s.Store.Unreadable(); reason != "" {
		t.Errorf("Unreadable = %q, want servable on the previous set", reason)
	}
}

// The exception above covers a set that was loaded and then went unconfirmed. A
// cold start has nothing to keep, so an unreachable keeper leaves the redactor
// empty with no way to know what it is missing.
func TestBothOpsAreRefusedWhenTheKeeperWasNeverReached(t *testing.T) {
	file := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"}, file)
	_ = k.Listener.Close()
	s := serverWith(t, k, file)
	s.Store.Reload()

	if s.Store.Count() != 0 {
		t.Fatalf("Count = %d, want an empty set", s.Store.Count())
	}
	if s.Store.Unreadable() == "" {
		t.Error("Unreadable = \"\", want refused: no value set was ever loaded")
	}
	peer := &sockutil.Peer{UID: 1000}
	for _, op := range []map[string]any{
		{"op": "redact", "text": "x"},
		{"op": "run", "cmd": []any{"true"}, "cwd": t.TempDir()},
	} {
		got := handle(s, op, peer)
		if got["error"] == nil {
			t.Errorf("%v was served, want refused", op["op"])
		}
	}
}

// An install whose operator has not written a secret yet is configured
// correctly: the file is there and was read, so nothing is missing. Both ops
// serve, and a ref no file defines is answered by unknown_secret rather than by
// this gate.
func TestBothOpsAreServedWhenEveryManagedFileLoadedAndHeldNothing(t *testing.T) {
	k := keepertest.New(t, map[string]string{})
	file := managedFile(t)
	k.SetFiles([]string{file})
	s := serverWith(t, k, file)
	s.Store.Reload()

	if reason := s.Store.Unreadable(); reason != "" {
		t.Errorf("Unreadable = %q, want served: the file is there and was read", reason)
	}
	peer := &sockutil.Peer{UID: 1000}
	if got := handle(s, map[string]any{"op": "redact", "text": "x"}, peer); got["error"] != nil {
		t.Errorf("redact was refused: %v", got["error"])
	}
	got := handle(s, map[string]any{
		"op": "run", "cmd": []any{"true"}, "cwd": t.TempDir(),
	}, peer)
	if failure, ok := got["error"].(map[string]string); ok && failure["code"] == "no_secrets" {
		t.Errorf("exec was refused: %v", failure)
	}
}

// A file that did not load may hold anything, so its contents went unread,
// redaction cannot be promised, and the store reports itself unservable.
func TestTheStoreIsUnservableWhenAManagedFileDidNotLoad(t *testing.T) {
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
	file := managedFile(t)
	k.SetFiles([]string{file})
	k.SetErrors([]string{file + ": could not decrypt"})
	s := serverWith(t, k, file)
	s.Store.Reload()

	if s.Store.Unreadable() == "" {
		t.Error("Unreadable = served, want refused: a file went unread")
	}
}

// The two that do not produce output depending on the set stay available, being
// what diagnosing a missing store needs.
func TestStatusAndListStayAvailableWhileNoManagedFileWasRead(t *testing.T) {
	s := newUnconfiguredServer(t, map[string]string{})
	peer := &sockutil.Peer{UID: 1000}
	for _, op := range []string{"status", "refs"} {
		if got := handle(s, map[string]any{"op": op}, peer); got["error"] != nil {
			t.Errorf("%s was refused: %v", op, got["error"])
		}
	}
}

// An operator asking is asking to be told, and being told is the whole of it: a
// converge run must not fail a host that manages no credentials.
func TestCheckPassesWhileTheValueSetIsEmpty(t *testing.T) {
	s := newUnconfiguredServer(t, map[string]string{})
	s.Config.Ssh.Key = ""
	if _, code := s.CheckOutput(); code != 0 {
		t.Error("a broker holding no values failed the audit")
	}
}

// Deliberately unbounded: refs and run are on this socket behind the
// same check, so a caller who could probe can instead name every ref and be
// handed every value. A throttle here would only slow the path nobody needs.
//
// Enough calls that a limiter with any usable burst would refuse one: a couple
// would pass against every throttle worth writing.
func TestRedactIsNotRateLimited(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"}, managedFile(t))
	peer := &sockutil.Peer{UID: 1000}
	for i := range 500 {
		if got := handle(s, map[string]any{"op": "redact", "text": "x"}, peer); got["error"] != nil {
			t.Fatalf("call %d was refused: %v", i+1, got["error"])
		}
	}
}

// The refusal's remedies have to be for the states that reach it. A store
// nobody has written yet is served rather than refused, so advice about writing
// a first file was advice for a condition this message cannot carry, and an
// operator whose age key had gone unreadable was told to create a secret.
func TestTheUnreadableRefusalAdvisesOnlyWhatCouldHaveCausedIt(t *testing.T) {
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
	file := managedFile(t)
	k.SetFiles([]string{file})
	k.SetErrors([]string{"/etc/faramir/secrets/other.sops.yml: could not decrypt"})
	s := serverWith(t, k, file)
	s.Store.Reload()

	got := handle(s, map[string]any{
		"op": "run", "cmd": []any{"true"}, "cwd": t.TempDir(),
	}, &sockutil.Peer{UID: 1000})
	failure, ok := got["error"].(map[string]string)
	if !ok || failure["code"] != "no_secrets" {
		t.Fatalf("wanted the no_secrets refusal, got %v", got)
	}
	if strings.Contains(failure["message"], "vault add") {
		t.Errorf("the refusal advises writing a first file, which is not a state "+
			"that reaches it: %q", failure["message"])
	}
	for _, want := range []string{"named above", "faramir doctor", "secret.link"} {
		if !strings.Contains(failure["message"], want) {
			t.Errorf("the refusal does not mention %q: %q", want, failure["message"])
		}
	}
}

// A refusal is what the operator reads when they ask why nothing ran, and the
// first thing they want from it is who was refused. Every other record carries
// the peer; this one did not, and a store that cannot be read produces a run of
// them, so the log filled with refusals attributed to nobody.
func TestTheUnreadableRefusalRecordsWhoWasRefused(t *testing.T) {
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
	file := managedFile(t)
	k.SetFiles([]string{file})
	k.SetErrors([]string{"/etc/faramir/secrets/other.sops.yml: could not decrypt"})
	s := serverWith(t, k, file)
	s.Store.Reload()

	peer := &sockutil.Peer{UID: 4242, GID: 4243, PID: 4244}
	if got := handle(s, map[string]any{
		"op": "run", "cmd": []any{"true"}, "cwd": t.TempDir(),
	}, peer); got["error"] == nil {
		t.Fatal("the run was not refused")
	}

	body, err := os.ReadFile(s.Config.Audit.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for line := range strings.Lines(string(body)) {
		var record struct {
			Refused string `json:"refused"`
			Peer    *struct {
				UID int `json:"uid"`
			} `json:"peer"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if record.Refused != "no_secrets" {
			continue
		}
		found = true
		if record.Peer == nil {
			t.Error("the refusal was recorded with no peer, so it says what happened " +
				"and not to whom")
		} else if record.Peer.UID != 4242 {
			t.Errorf("the record names uid %d, want 4242", record.Peer.UID)
		}
	}
	if !found {
		t.Errorf("no no_secrets record was written: %s", body)
	}
}

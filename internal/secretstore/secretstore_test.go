package secretstore

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sockutil"
)

// fakeKeeper serves whatever value set the test sets, so the load gate can be
// exercised without sops, an age key, or a real keeper.
type fakeKeeper struct {
	mu     sync.Mutex
	values map[string]string
	errors []string
	ln     net.Listener
	path   string
}

func newFakeKeeper(t *testing.T, values map[string]string) *fakeKeeper {
	t.Helper()
	return serveFakeKeeper(t, filepath.Join(t.TempDir(), "keeper.sock"), values)
}

// serveFakeKeeper binds a named socket, so a test can start one *after* the
// store has already tried and failed to reach it.
func serveFakeKeeper(t *testing.T, path string, values map[string]string) *fakeKeeper {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	k := &fakeKeeper{values: values, ln: ln, path: path}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read the request before answering, as the real keeper does.
			// Closing while the client is still writing gives it EPIPE, which
			// surfaces as an intermittently empty value set.
			_, _ = sockutil.ReadLine(conn, 1<<16)
			k.mu.Lock()
			errors := k.errors
			if errors == nil {
				errors = []string{}
			}
			payload := map[string]any{"values": k.values, "errors": errors}
			k.mu.Unlock()
			_ = sockutil.Send(conn, payload)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return k
}

func (k *fakeKeeper) set(values map[string]string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.values = values
}

func (k *fakeKeeper) setErrors(errors []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.errors = errors
}

func newStore(t *testing.T, keeper *fakeKeeper, files ...string) *Store {
	t.Helper()
	return New(
		config.SecretsConfig{
			Files: files, RefreshIntervalSec: 0,
			MinLength: 8, MinUniqueChars: 4, MinEntropyBitsPerChar: 1.5,
		},
		config.KeeperConfig{SocketPath: keeper.path},
	)
}

// -- the load gate ----------------------------------------------------------

func TestARedactableValueIsLoaded(t *testing.T) {
	k := newFakeKeeper(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s := newStore(t, k)
	s.Reload()

	got, err := s.Value("a/b")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2-correct-horse" {
		t.Errorf("value = %q", got)
	}
	if refs := s.Refs(); len(refs) != 1 || refs[0] != "a/b" {
		t.Errorf("refs = %v", refs)
	}
}

func TestAShortValueIsRefused(t *testing.T) {
	k := newFakeKeeper(t, map[string]string{"tiny": "abc"})
	s := newStore(t, k)
	s.Reload()

	if refs := s.Refs(); len(refs) != 0 {
		t.Errorf("a short value was listed: %v", refs)
	}
	_, err := s.Value("tiny")
	if err == nil {
		t.Fatal("a short value was injectable")
	}
	if !strings.Contains(err.Error(), "refused at load") {
		t.Errorf("message = %q", err.Error())
	}
}

func TestALowEntropyValueIsRefused(t *testing.T) {
	k := newFakeKeeper(t, map[string]string{"flat": "abababababababab"})
	s := newStore(t, k)
	s.Reload()
	if _, err := s.Value("flat"); err == nil {
		t.Fatal("a low-entropy value was injectable")
	}
}

// The refusal and the typo have to read differently, or the operator goes
// looking for a misspelling in a ref that is spelled right.
func TestAnUnknownRefIsNotReportedAsRefused(t *testing.T) {
	k := newFakeKeeper(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s := newStore(t, k)
	s.Reload()

	_, err := s.Value("nope")
	if err == nil {
		t.Fatal("an unknown ref resolved")
	}
	if !strings.Contains(err.Error(), "unknown secret ref") {
		t.Errorf("message = %q", err.Error())
	}
	if strings.Contains(err.Error(), "refused at load") {
		t.Error("an unknown ref was reported as refused")
	}
}

// A value that is never tokenized is one worth targeting, so the agent-facing
// summary must not name it.
func TestTheAgentFacingSummaryDoesNotNameThem(t *testing.T) {
	k := newFakeKeeper(t, map[string]string{
		"good": "hunter2-correct-horse", "tiny": "abc",
	})
	s := newStore(t, k)
	s.Reload()

	body, err := json.Marshal(s.Describe())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "tiny") {
		t.Errorf("the agent-facing summary named a refused ref: %s", body)
	}
	if strings.Contains(string(body), "not_redactable") {
		t.Errorf("the agent-facing summary carried the refusal list: %s", body)
	}
}

func TestTheOperatorSummaryNamesThemAndTheReason(t *testing.T) {
	k := newFakeKeeper(t, map[string]string{"tiny": "abc"})
	s := newStore(t, k)
	s.Reload()

	out := s.DescribeForOperator()
	refused, ok := out["not_redactable"].(map[string]string)
	if !ok {
		t.Fatalf("not_redactable = %T", out["not_redactable"])
	}
	reason, ok := refused["tiny"]
	if !ok {
		t.Fatalf("tiny not named: %v", refused)
	}
	if !strings.Contains(reason, "shorter than") {
		t.Errorf("reason = %q", reason)
	}
}

func TestARefusalDoesNotSurviveAReloadThatFixesIt(t *testing.T) {
	k := newFakeKeeper(t, map[string]string{"x": "abc"})
	s := newStore(t, k)
	s.Reload()
	if _, err := s.Value("x"); err == nil {
		t.Fatal("the short value was injectable")
	}

	k.set(map[string]string{"x": "hunter2-correct-horse"})
	s.Reload()
	if _, err := s.Value("x"); err != nil {
		t.Fatalf("the lengthened value is still refused: %v", err)
	}
	out := s.DescribeForOperator()
	if refused := out["not_redactable"].(map[string]string); len(refused) != 0 {
		t.Errorf("the stale refusal survived: %v", refused)
	}
}

// An unreachable keeper must not blank the value set: an empty set means
// nothing is redacted, which is the worst possible response to a brief outage.
func TestAnUnreachableKeeperKeepsThePreviousValueSet(t *testing.T) {
	k := newFakeKeeper(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s := newStore(t, k)
	s.Reload()

	_ = k.ln.Close()
	s.Reload()

	if got, err := s.Value("a/b"); err != nil || got != "hunter2-correct-horse" {
		t.Errorf("the value set was dropped: %q %v", got, err)
	}
	if len(s.LoadErrors) == 0 {
		t.Error("the failure was not reported")
	}
}

// And it must recover on its own once the keeper is back.  The files have not
// changed, only our ability to decrypt them, so the mtime poll alone would
// never notice: on a cold start that leaves an empty value set, and an empty
// value set redacts nothing.
func TestAKeeperThatComesBackIsPickedUpWithoutASighup(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "v.sops.yml")
	if err := os.WriteFile(managed, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Cold start: nothing is listening yet, so the first load fails outright.
	sock := filepath.Join(dir, "keeper.sock")
	s := New(
		config.SecretsConfig{
			Files: []string{managed}, RefreshIntervalSec: 0,
			MinLength: 8, MinUniqueChars: 4, MinEntropyBitsPerChar: 1.5,
		},
		config.KeeperConfig{SocketPath: sock},
	)
	s.Reload()
	if len(s.Refs()) != 0 {
		t.Fatalf("refs = %v, want none before the keeper exists", s.Refs())
	}

	serveFakeKeeper(t, sock, map[string]string{"x": "hunter2-correct-horse"})
	// No edit, no SIGHUP: only the retry may recover this.
	s.RefreshIfStale()

	if got, err := s.Value("x"); err != nil || got != "hunter2-correct-horse" {
		t.Errorf("the store did not recover once the keeper was up: %q %v", got, err)
	}
}

// refresh_interval_sec may be 0, which asks for a check on every request, so
// the interval alone cannot bound the work.  Concurrent requests must not each
// start their own keeper round trip and sops exec.
func TestConcurrentRefreshesDoNotStampedeTheKeeper(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "keeper.sock")
	s := New(
		config.SecretsConfig{
			RefreshIntervalSec: 0,
			MinLength:          8, MinUniqueChars: 4, MinEntropyBitsPerChar: 1.5,
		},
		config.KeeperConfig{SocketPath: sock},
	)
	s.Reload() // fails: nothing is listening, so every later poll wants a retry

	var served atomic.Int32
	// serving closes once a reload is inside the keeper call; release holds it
	// there.  Sequencing it rather than sleeping is what keeps this from
	// passing on a loaded machine simply because the other callers arrived
	// after the first one had already finished.
	serving := make(chan struct{})
	release := make(chan struct{})

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read the request before answering, as the real keeper does.
			// Closing while the client is still writing gives it EPIPE.
			_, _ = sockutil.ReadLine(conn, 1<<16)
			if served.Add(1) == 1 {
				close(serving)
				<-release
			}
			_ = sockutil.Send(conn, map[string]any{
				"values": map[string]string{"x": "hunter2-correct-horse"},
				"errors": []string{},
			})
			_ = conn.Close()
		}
	}()

	var winner sync.WaitGroup
	winner.Add(1)
	go func() {
		defer winner.Done()
		s.RefreshIfStale()
	}()
	<-serving // the winner now holds the guard, mid-keeper-call

	var others sync.WaitGroup
	for range 7 {
		others.Add(1)
		go func() {
			defer others.Done()
			s.RefreshIfStale()
		}()
	}
	// These must all return while the winner is still blocked.  If any of them
	// dialled the keeper instead, it would block on release and time this out.
	done := make(chan struct{})
	go func() { others.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a concurrent RefreshIfStale started its own keeper call")
	}

	close(release)
	winner.Wait()

	if n := served.Load(); n != 1 {
		t.Errorf("the keeper served %d reloads, want 1", n)
	}
	if got, err := s.Value("x"); err != nil || got != "hunter2-correct-horse" {
		t.Errorf("the one reload that ran did not land: %q %v", got, err)
	}
}

// Pairs is the redactor's input: every managed value, not just injected ones.
func TestPairsCarriesEveryLoadedValue(t *testing.T) {
	k := newFakeKeeper(t, map[string]string{
		"a": "hunter2-correct-horse", "b": "another-good-value", "tiny": "abc",
	})
	s := newStore(t, k)
	s.Reload()

	pairs := s.Pairs()
	if len(pairs) != 2 {
		t.Fatalf("pairs = %v", pairs)
	}
	for _, p := range pairs {
		if p.Ref == "tiny" {
			t.Error("a refused value reached the redactor")
		}
	}
}

// A missing managed file is reported, not fatal.
func TestAMissingFileIsReported(t *testing.T) {
	k := newFakeKeeper(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s := newStore(t, k, filepath.Join(t.TempDir(), "absent.sops.yml"))
	s.Reload()

	if len(s.LoadErrors) == 0 {
		t.Error("a missing file was not reported")
	}
	if _, err := s.Value("a/b"); err != nil {
		t.Errorf("the value set was lost over a missing file: %v", err)
	}
	// The installer runs --check before any store exists, so the one file it is
	// configured for does not exist yet.  Treating that as a failure would make
	// a first install impossible.
	if fatal := s.FatalLoadErrors(); len(fatal) != 0 {
		t.Errorf("an absent file was treated as a broken install: %v", fatal)
	}
}

// A file that exists and cannot be read is the case worth failing on: the
// broker comes up serving fewer values than it is configured for, and every
// value it did not load is one it cannot redact.
func TestAnUnreadableFileIsFatal(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "regular")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := newFakeKeeper(t, map[string]string{"a/b": "hunter2-correct-horse"})
	// Stat fails with ENOTDIR rather than ENOENT, which is the distinction.
	s := newStore(t, k, filepath.Join(notADir, "v.sops.yml"))
	s.Reload()

	if len(s.FatalLoadErrors()) == 0 {
		t.Error("a file that could not be stat'd was reported as a healthy install")
	}
}

// The keeper runs as its own uid and may not be able to traverse the path to a
// managed file, in which case it reports EACCES for a file that does not exist.
// The broker can stat it, so it is the one that can tell the difference, and a
// file that is not there yet is a store nobody has written.
func TestAKeeperErrorAboutAMissingFileIsNotFatal(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent.sops.yml")
	k := newFakeKeeper(t, map[string]string{"a/b": "hunter2-correct-horse"})
	k.setErrors([]string{absent + ": decrypt failed (2): Error reading file: open " +
		absent + ": permission denied"})
	s := newStore(t, k, absent)
	s.Reload()

	if fatal := s.FatalLoadErrors(); len(fatal) != 0 {
		t.Errorf("a keeper error about a file that does not exist was treated as a "+
			"broken install: %v", fatal)
	}
	if len(s.LoadErrors) == 0 {
		t.Error("the keeper error was dropped instead of reported")
	}
}

// The loosening above is scoped to a file the broker found absent.  One that is
// there and did not decrypt still leaves the broker unable to redact its value.
func TestAKeeperErrorAboutAnExistingFileIsFatal(t *testing.T) {
	managed := filepath.Join(t.TempDir(), "v.sops.yml")
	if err := os.WriteFile(managed, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := newFakeKeeper(t, map[string]string{"a/b": "hunter2-correct-horse"})
	k.setErrors([]string{managed + ": decrypt failed (2): no key"})
	s := newStore(t, k, managed)
	s.Reload()

	if len(s.FatalLoadErrors()) == 0 {
		t.Error("a file that exists and did not decrypt was reported as a healthy install")
	}
}

// The loosening is scoped by reason as well as by path.  The two processes are
// separately sandboxed and can disagree about whether a file exists, so a
// reason only a file the keeper did read can produce stays fatal: downgrading
// it would leave the broker running with values missing from the redactor,
// which is what --check exists to catch.
func TestAKeeperErrorAMissingFileCannotExplainIsFatal(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent.sops.yml")
	k := newFakeKeeper(t, map[string]string{"a/b": "hunter2-correct-horse"})
	k.setErrors([]string{absent + ": decrypted output is not JSON: unexpected end of JSON input"})
	s := newStore(t, k, absent)
	s.Reload()

	if len(s.FatalLoadErrors()) == 0 {
		t.Error("a file the keeper decrypted was written off as not yet created")
	}
}

// Stat follows symlinks, so a managed file whose target was moved reports
// ENOENT for a path that is really there.  That is a broken install rather than
// an absent store, and it must not silence the keeper's error.
func TestADanglingSymlinkIsFatal(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "v.sops.yml")
	if err := os.Symlink(filepath.Join(dir, "moved.sops.yml"), managed); err != nil {
		t.Fatal(err)
	}
	k := newFakeKeeper(t, map[string]string{"a/b": "hunter2-correct-horse"})
	k.setErrors([]string{managed + ": decrypt failed (2): Error reading file: no such file"})
	s := newStore(t, k, managed)
	s.Reload()

	if len(s.FatalLoadErrors()) == 0 {
		t.Error("a managed file whose symlink target is gone was reported as a healthy install")
	}
}

// The mtime poll is what picks up an edit without a SIGHUP.
func TestRefreshIfStaleReloadsOnAChangedFile(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "v.sops.yml")
	if err := os.WriteFile(managed, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := newFakeKeeper(t, map[string]string{"x": "hunter2-correct-horse"})
	s := newStore(t, k, managed)
	s.Reload()

	k.set(map[string]string{"x": "a-different-good-value"})
	// Same size would leave mtime as the only signal, and some filesystems
	// have coarse timestamps; change the size too.
	if err := os.WriteFile(managed, []byte("aa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.RefreshIfStale()

	if got, _ := s.Value("x"); got != "a-different-good-value" {
		t.Errorf("value = %q; the edit was not picked up", got)
	}
}

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
	"github.com/andornaut/faramir/internal/keepertest"
	"github.com/andornaut/faramir/internal/sockutil"
)

// newStore configures a store against a stand-in keeper, both given the same
// file list: the store no longer stats those files itself.
func newStore(t *testing.T, fake *keepertest.Keeper, files ...string) *Store {
	t.Helper()
	fake.SetFiles(files)
	return New(
		config.SecretsConfig{
			Patterns: files, RefreshIntervalSec: 0,
			MinLength: 8,
		},
		config.KeeperConfig{SocketPath: fake.Path},
	)
}

// -- the load gate ----------------------------------------------------------

func TestARedactableValueIsLoaded(t *testing.T) {
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
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
	k := keepertest.New(t, map[string]string{"tiny": "abc"})
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

// A value long enough to redact is carried whatever it looks like.  The store
// refuses what it cannot cover, not what it disapproves of: a weak credential
// is the operator's to fix, and refusing to serve one would leave a project
// with no value where it expected one and nothing this end could do about it.
func TestALowEntropyValueIsCarried(t *testing.T) {
	k := keepertest.New(t, map[string]string{"flat": "abababababababab"})
	s := newStore(t, k)
	s.Reload()
	if _, err := s.Value("flat"); err != nil {
		t.Fatalf("a long but low-entropy value was refused: %v", err)
	}
}

// A refused ref must not read as a typo.
func TestAnUnknownRefIsNotReportedAsRefused(t *testing.T) {
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
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

// A value that is never tokenized is worth targeting, so the agent-facing
// summary does not name it.
func TestTheAgentFacingSummaryDoesNotNameThem(t *testing.T) {
	k := keepertest.New(t, map[string]string{
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
	k := keepertest.New(t, map[string]string{"tiny": "abc"})
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
	k := keepertest.New(t, map[string]string{"x": "abc"})
	s := newStore(t, k)
	s.Reload()
	if _, err := s.Value("x"); err == nil {
		t.Fatal("the short value was injectable")
	}

	k.SetValues(map[string]string{"x": "hunter2-correct-horse"})
	s.Reload()
	if _, err := s.Value("x"); err != nil {
		t.Fatalf("the lengthened value is still refused: %v", err)
	}
	out := s.DescribeForOperator()
	if refused := out["not_redactable"].(map[string]string); len(refused) != 0 {
		t.Errorf("the stale refusal survived: %v", refused)
	}
}

// An empty value set redacts nothing, so a brief outage keeps the old one.
func TestAnUnreachableKeeperKeepsThePreviousValueSet(t *testing.T) {
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s := newStore(t, k)
	s.Reload()

	_ = k.Listener.Close()
	s.Reload()

	if got, err := s.Value("a/b"); err != nil || got != "hunter2-correct-horse" {
		t.Errorf("the value set was dropped: %q %v", got, err)
	}
	if len(s.LoadErrors()) == 0 {
		t.Error("the failure was not reported")
	}
}

// And recovers on its own: the files have not changed, only the ability to
// decrypt them, so the mtime poll would never notice.
func TestAKeeperThatComesBackIsPickedUpWithoutASighup(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "v.sops.yml")
	if err := os.WriteFile(managed, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Cold start: nothing is listening, so the first load fails.
	sock := filepath.Join(dir, "keeper.sock")
	s := New(
		config.SecretsConfig{
			Patterns: []string{managed}, RefreshIntervalSec: 0,
			MinLength: 8,
		},
		config.KeeperConfig{SocketPath: sock},
	)
	s.Reload()
	if len(s.Refs()) != 0 {
		t.Fatalf("refs = %v, want none before the keeper exists", s.Refs())
	}

	keepertest.Serve(t, sock, map[string]string{"x": "hunter2-correct-horse"})
	// No edit, no SIGHUP: only the retry recovers this.
	s.RefreshIfStale()

	if got, err := s.Value("x"); err != nil || got != "hunter2-correct-horse" {
		t.Errorf("the store did not recover once the keeper was up: %q %v", got, err)
	}
}

// refresh_interval_sec may be 0, so concurrent requests must not each start a
// keeper round trip and sops exec.
func TestConcurrentRefreshesDoNotStampedeTheKeeper(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "keeper.sock")
	s := New(
		config.SecretsConfig{
			RefreshIntervalSec: 0,
			MinLength:          8,
		},
		config.KeeperConfig{SocketPath: sock},
	)
	s.Reload() // fails: nothing is listening, so every later poll wants a retry

	var served atomic.Int32
	// serving closes once a reload is inside the keeper call; release holds it
	// there.  Sequenced rather than slept, so a loaded machine cannot pass this
	// by arriving late.
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
			// Read before answering: closing mid-write gives the client
			// EPIPE.
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
	// All must return while the winner is still blocked; one that dialled the
	// keeper would block on release.
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
	k := keepertest.New(t, map[string]string{
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

// An unmounted store is indistinguishable from one never written, and both
// leave the broker redacting nothing while looking healthy.
func TestAMissingFileIsUnresolvedRatherThanALoadError(t *testing.T) {
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s := newStore(t, k, filepath.Join(t.TempDir(), "absent.sops.yml"))
	s.Reload()

	// Not a load error: the daemon starts on this, a store not written yet being
	// what a first install looks like.
	if errs := s.LoadErrors(); len(errs) != 0 {
		t.Errorf("LoadErrors = %v, want none", errs)
	}
	// Reported instead.  What the empty value set then refuses is a server
	// concern, tested there; this double serves its values whatever the file
	// list says.
	if len(s.UnresolvedPatterns()) == 0 {
		t.Error("a missing file was reported as a healthy install")
	}
}

// Every other way the stat can fail is the same failure.
func TestAnUnreadableFileIsUnresolvedToo(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "regular")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s := newStore(t, k, filepath.Join(notADir, "v.sops.yml"))
	s.Reload()

	if len(s.UnresolvedPatterns()) == 0 {
		t.Error("a file that could not be stat'd was reported as a healthy install")
	}
}

// The two processes are separately sandboxed and can disagree about whether a
// path exists, so the keeper's report stands on its own.
func TestAKeeperErrorIsFatal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		exists  bool
		failure string
	}{
		{"a file that did not decrypt", true, "decrypt failed (2): no key"},
		{"a file the keeper could not reach", false, "decrypt failed (2): permission denied"},
		{"output the keeper could not parse", false, "decrypted output is not JSON"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			managed := filepath.Join(t.TempDir(), "v.sops.yml")
			if tc.exists {
				if err := os.WriteFile(managed, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
			k.SetErrors([]string{managed + ": " + tc.failure})
			s := newStore(t, k, managed)
			s.Reload()

			if len(s.LoadErrors()) == 0 {
				t.Error("reported as a healthy install")
			}
		})
	}
}

// The mtime poll is what picks up an edit without a SIGHUP.
func TestRefreshIfStaleReloadsOnAChangedFile(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "v.sops.yml")
	if err := os.WriteFile(managed, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := keepertest.New(t, map[string]string{"x": "hunter2-correct-horse"})
	s := newStore(t, k, managed)
	s.Reload()

	k.SetValues(map[string]string{"x": "a-different-good-value"})
	// Some filesystems have coarse timestamps, so change the size too.
	if err := os.WriteFile(managed, []byte("aa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.RefreshIfStale()

	if got, _ := s.Value("x"); got != "a-different-good-value" {
		t.Errorf("value = %q; the edit was not picked up", got)
	}
}

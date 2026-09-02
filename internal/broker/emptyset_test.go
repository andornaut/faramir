package broker

// An empty value set.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/execclient"
	"github.com/andornaut/faramir/internal/keepertest"
	"github.com/andornaut/faramir/internal/sockutil"
)

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
// refusing on it would turn a keeper hiccup into refused commands.
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

// A run whose executor vanished before reporting a status carries the stand-in
// marker into the response, so a caller can tell the non-zero code from a
// signal kill. A finished run does not.
func TestExecResponseMarksAnUnknownStatus(t *testing.T) {
	unknown := execResponse("log1", execEscalation{},
		&execclient.Result{ExitCode: 137, StatusUnknown: true})
	if unknown["status_unknown"] != true {
		t.Errorf("status_unknown = %v, want true", unknown["status_unknown"])
	}
	known := execResponse("log2", execEscalation{},
		&execclient.Result{ExitCode: 0})
	if _, ok := known["status_unknown"]; ok {
		t.Errorf("status_unknown present on a finished run: %v", known["status_unknown"])
	}
}

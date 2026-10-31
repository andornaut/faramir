package secretstore

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keepertest"
	"github.com/andornaut/faramir/internal/redact"
)

func TestSnapshotRetainsValuesAndMatcherAcrossReload(t *testing.T) {
	const oldValue = "synthetic-before-rotation"
	const newValue = "synthetic-after-rotation"
	k := keepertest.New(t, map[string]string{"svc/token": oldValue, "tiny": "abc"})
	s := newStore(t, k)
	s.Reload()
	snapshot := s.Snapshot()

	k.SetValues(map[string]string{"svc/token": newValue, "tiny": newValue})
	s.Reload()
	if got, err := snapshot.Value("svc/token"); err != nil || got != oldValue {
		t.Fatalf("snapshot changed after reload: %q, %v", got, err)
	}
	if got, err := s.Value("svc/token"); err != nil || got != newValue {
		t.Fatalf("store did not update: %q, %v", got, err)
	}
	if _, err := snapshot.Value("tiny"); err == nil || !strings.Contains(err.Error(), "refused at load") {
		t.Fatalf("snapshot lost its refusal: %v", err)
	}
	if _, err := s.Value("tiny"); err != nil {
		t.Fatalf("store retained its old refusal: %v", err)
	}
	input := oldValue + " " + newValue
	if got := snapshot.Redactor().RedactText(input); got != redact.TokenFor("svc/token")+" "+newValue {
		t.Fatalf("snapshot used a different matcher: %q", got)
	}
	if got := s.Redactor().RedactText(input); got != oldValue+" "+redact.TokenFor("svc/token") {
		t.Fatalf("store retained its old matcher: %q", got)
	}
	if len(snapshot.Redactor().Summary()) != 0 {
		t.Fatal("snapshot shared mutable redactor counts")
	}
}

func TestSnapshotRetainsHealthAcrossReload(t *testing.T) {
	k := keepertest.New(t, map[string]string{"svc/token": "synthetic-test-value"})
	s := newStore(t, k)
	s.Reload()
	healthy := s.Snapshot()
	k.SetErrors([]string{"synthetic load failure"})
	s.Reload()
	failed := s.Snapshot()
	if healthy.Unreadable() != "" || failed.Unreadable() == "" || failed.Unreadable() != s.Unreadable() {
		t.Fatal("snapshot health did not match its generation")
	}
	k.SetErrors(nil)
	s.Reload()
	if s.Unreadable() != "" || failed.Unreadable() == "" {
		t.Fatal("recovery changed an earlier snapshot or failed to update the store")
	}
}

func TestSnapshotClonesLookupMaps(t *testing.T) {
	s := New(config.SecretConfig{MinLength: 8}, config.KeeperConfig{})
	s.values["svc/token"] = "synthetic-initial-value"
	s.refused["tiny"] = "synthetic refusal"
	s.degradedLinks["linked"] = "synthetic link failure"
	snapshot := s.Snapshot()
	s.mu.Lock()
	s.values["svc/token"] = "synthetic-replacement-value"
	delete(s.refused, "tiny")
	delete(s.degradedLinks, "linked")
	s.mu.Unlock()
	if got, _ := snapshot.Value("svc/token"); got != "synthetic-initial-value" {
		t.Fatal("snapshot aliased the store's values")
	}
	for _, ref := range []string{"tiny", "linked", "unknown"} {
		_, err := snapshot.Value(ref)
		if err == nil {
			t.Fatalf("snapshot resolved %s", ref)
		}
		if ref != "unknown" && strings.Contains(err.Error(), "unknown secret ref") {
			t.Fatalf("snapshot lost the reason for %s", ref)
		}
	}
}

func TestSnapshotPreservesUnconfirmedHealth(t *testing.T) {
	for _, loaded := range []bool{false, true} {
		s := New(config.SecretConfig{}, config.KeeperConfig{})
		s.unconfirmed = true
		s.loadErrors = []string{"synthetic keeper failure"}
		if loaded {
			s.state = []fileState{{Path: "synthetic-managed-file"}}
		}
		snapshot := s.Snapshot()
		if got := snapshot.Unreadable(); got != s.Unreadable() || (got == "") != loaded {
			t.Fatalf("loaded=%v: unexpected snapshot health %q", loaded, got)
		}
		s.mu.Lock()
		s.unconfirmed = false
		s.loadErrors = nil
		s.state = nil
		s.mu.Unlock()
		if !loaded && snapshot.Unreadable() == "" {
			t.Fatal("snapshot lost its unconfirmed health")
		}
		if got := snapshot.Redactor().RedactText("plain output"); got != "plain output" {
			t.Fatalf("empty snapshot redactor changed output: %q", got)
		}
	}
}

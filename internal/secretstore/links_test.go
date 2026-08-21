package secretstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keepertest"
	"github.com/andornaut/faramir/internal/secretlink"
)

// newLinkedStore is newStore with links as well, and a managed inventory that
// may be empty: an install whose only secrets are linked is a legitimate one.
func newLinkedStore(t *testing.T, fake *keepertest.Keeper, links []config.Link,
	files ...string) *Store {
	t.Helper()
	fake.SetFiles(files)
	return New(
		config.SecretConfig{
			Patterns: files, Links: links, MinRefreshSec: 0, MinLength: 8,
		},
		config.KeeperConfig{SocketPath: fake.Path},
	)
}

// writeLinked puts a file where a link can read it and returns the path.
func writeLinked(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// managedFile is a sops file that exists, for the tests that need the managed
// half of the store to be serving. The stand-in keeper stats what it is given,
// so a name alone would report as an entry that matched nothing.
func managedFile(t *testing.T) string {
	t.Helper()
	return writeLinked(t, "managed.sops.yml", "ciphertext\n")
}

func TestALinkedValueJoinsTheValueSet(t *testing.T) {
	path := writeLinked(t, "hosts.yml",
		"github.com:\n    oauth_token: gho_linked_example\n    user: someone\n")
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s := newLinkedStore(t, k, []config.Link{{
		Ref: "gh/token", Path: path, Type: secretlink.KindYAML,
		Key: "github.com/oauth_token",
	}})
	s.Reload()

	got, err := s.Value("gh/token")
	if err != nil {
		t.Fatal(err)
	}
	if got != "gho_linked_example" {
		t.Errorf("value = %q", got)
	}
	// Both sources in one namespace, and one flat list of names.
	if refs := s.Refs(); len(refs) != 2 {
		t.Errorf("refs = %v, want the managed one and the linked one", refs)
	}
	// The redactor is handed both, which is the point of linking at all.
	var linked bool
	for _, pair := range s.Pairs() {
		if pair.Ref == "gh/token" && pair.Value == "gho_linked_example" {
			linked = true
		}
	}
	if !linked {
		t.Error("the linked value is not in the redactor's set")
	}
}

// The gate the operator chose: a link that is there and will not read is a
// value the redactor is missing, so the broker refuses to serve.
func TestAnUnreadableLinkRefusesTheStore(t *testing.T) {
	path := writeLinked(t, "hosts.yml", "not: yaml: at: all: [")
	managed := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"}, managed)
	s := newLinkedStore(t, k, []config.Link{{
		Ref: "gh/token", Path: path, Type: secretlink.KindYAML, Key: "github.com/oauth_token",
	}}, managed)
	s.Reload()

	reason := s.Unreadable()
	if reason == "" {
		t.Fatal("a link that would not parse left the store serving")
	}
	if !strings.Contains(reason, "gh/token") {
		t.Errorf("the refusal does not name the link: %s", reason)
	}
	// The managed value is still held: one broken link does not blank the set.
	if _, err := s.Value("a/b"); err != nil {
		t.Errorf("a broken link dropped a managed value: %v", err)
	}
}

// A link whose file has gone is the other meaning: the credential is off the
// machine, so there is nothing left to redact. Reported, not fatal.
func TestALinkNamingNothingIsReportedAndNotFatal(t *testing.T) {
	managed := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"}, managed)
	s := newLinkedStore(t, k, []config.Link{{
		Ref: "gh/token", Path: filepath.Join(t.TempDir(), "gone.yml"),
		Type: secretlink.KindYAML, Key: "github.com/oauth_token",
	}}, managed)
	s.Reload()

	if reason := s.Unreadable(); reason != "" {
		t.Errorf("an absent link refused the store: %s", reason)
	}
	unresolved := strings.Join(s.UnresolvedPatterns(), "; ")
	if !strings.Contains(unresolved, "gh/token") {
		t.Errorf("an absent link went unreported: %v", s.UnresolvedPatterns())
	}
}

// A store whose only secrets are linked serves. Without this an install that
// has written no sops file yet but does link one credential would refuse every
// command.
func TestLinksAloneAreEnoughToServe(t *testing.T) {
	path := writeLinked(t, "token", "gho_linked_example\n")
	k := keepertest.New(t, map[string]string{})
	s := newLinkedStore(t, k, []config.Link{{
		Ref: "gh/token", Path: path, Type: secretlink.KindText,
	}})
	s.Reload()

	if reason := s.Unreadable(); reason != "" {
		t.Fatalf("a store holding one linked value refused to serve: %s", reason)
	}
	if s.Count() != 1 {
		t.Errorf("count = %d, want the linked value", s.Count())
	}
}

// A store with neither says so, rather than reporting an empty inventory as a
// missing file.
func TestNeitherPatternsNorLinksIsNamed(t *testing.T) {
	k := keepertest.New(t, map[string]string{})
	s := newLinkedStore(t, k, nil)
	s.Reload()

	reason := s.Unreadable()
	if !strings.Contains(reason, "[[secret.link]]") {
		t.Errorf("the refusal does not mention links: %s", reason)
	}
}

// A linked value is held to the length gate the managed ones are: it is served
// out of the same map and matched by the same redactor.
func TestAShortLinkedValueIsRefused(t *testing.T) {
	path := writeLinked(t, "token", "abc\n")
	k := keepertest.New(t, map[string]string{})
	s := newLinkedStore(t, k, []config.Link{{
		Ref: "short/token", Path: path, Type: secretlink.KindText,
	}})
	s.Reload()

	if refs := s.Refs(); len(refs) != 0 {
		t.Errorf("a short linked value was listed: %v", refs)
	}
	if _, err := s.Value("short/token"); err == nil ||
		!strings.Contains(err.Error(), "refused at load") {
		t.Errorf("error = %v, want the refusal the managed values get", err)
	}
}

// Blocked rather than resolved either way: one of the two would then rotate
// with nothing reading it.
func TestALinkShadowingAManagedRefIsRefused(t *testing.T) {
	path := writeLinked(t, "token", "gho_linked_example\n")
	managed := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"}, managed)
	s := newLinkedStore(t, k, []config.Link{{
		Ref: "a/b", Path: path, Type: secretlink.KindText,
	}}, managed)
	s.Reload()

	reason := s.Unreadable()
	if reason == "" {
		t.Fatal("a link shadowing a managed ref was accepted")
	}
	if !strings.Contains(reason, "a/b") {
		t.Errorf("the refusal does not name the ref: %s", reason)
	}
	// The managed value wins, so the redactor still covers what sops holds.
	if got, err := s.Value("a/b"); err != nil || got != "hunter2-correct-horse" {
		t.Errorf("value = (%q, %v), want the managed one", got, err)
	}
}

// The broker stats these itself, so an edit is noticed without a keeper round
// trip.
func TestAnEditedLinkIsPickedUp(t *testing.T) {
	path := writeLinked(t, "token", "gho_first_example\n")
	k := keepertest.New(t, map[string]string{})
	s := newLinkedStore(t, k, []config.Link{{
		Ref: "gh/token", Path: path, Type: secretlink.KindText,
	}})
	s.Reload()

	if err := os.WriteFile(path, []byte("gho_second_example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.RefreshIfStale()

	got, err := s.Value("gh/token")
	if err != nil {
		t.Fatal(err)
	}
	if got != "gho_second_example" {
		t.Errorf("value = %q, want the edited one", got)
	}
}

// The paths are the operator's own files, in their home and refused to the
// agent's file tools, so the agent-facing summary counts them and does not say
// where they are.
func TestDescribeCountsLinksAndNamesThemOnlyToTheOperator(t *testing.T) {
	path := writeLinked(t, "token", "gho_linked_example\n")
	k := keepertest.New(t, map[string]string{})
	s := newLinkedStore(t, k, []config.Link{{
		Ref: "gh/token", Path: path, Type: secretlink.KindText,
	}})
	s.Reload()

	described := s.Describe()
	if described["links"] != 1 {
		t.Errorf("links = %v, want 1", described["links"])
	}
	for key, value := range described {
		if strings.Contains(strings.ToLower(key), "link") {
			continue
		}
		if text, ok := value.(string); ok && strings.Contains(text, path) {
			t.Errorf("the agent-facing summary names a linked file under %q", key)
		}
	}
	if _, named := described["linked_files"]; named {
		t.Error("the agent-facing summary names the linked files")
	}

	operator := s.DescribeForOperator()
	linked, ok := operator["linked_files"].(map[string]string)
	if !ok || linked["gh/token"] != path {
		t.Errorf("linked_files = %v, want gh/token at %s", operator["linked_files"], path)
	}
}

// A link that stats and will not read still has to be fingerprinted. The poll
// records every file that is there, so one left out of the loaded state differs
// from the poll's view on every request: a full reload, and a log line naming a
// change that never happened, forever.
func TestAnUnreadableLinkIsStillFingerprinted(t *testing.T) {
	path := writeLinked(t, "hosts.yml", "not: yaml: at: all: [")
	managed := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"}, managed)
	s := newLinkedStore(t, k, []config.Link{{
		Ref: "gh/token", Path: path, Type: secretlink.KindYAML, Key: "github.com/oauth_token",
	}}, managed)
	s.Reload()

	// The state the poll would compare against, and the state the poll computes,
	// have to agree while nothing has changed.
	before := s.linkState
	if len(before) != 1 {
		t.Fatalf("linkState = %v, want the file that is there", before)
	}
	current := statLinks(s.config.Links)
	if len(current) != len(before) || current[0] != before[0] {
		t.Errorf("the poll sees %v where the load recorded %v, so every request "+
			"would reload", current, before)
	}
}

// An install whose only secrets are linked holds its whole value set without
// the keeper contributing anything, so a keeper that cannot be reached leaves
// nothing unconfirmed and nothing to refuse over.
func TestALinksOnlyStoreServesWhenTheKeeperGoesAway(t *testing.T) {
	path := writeLinked(t, "token", "gho_linked_example\n")
	k := keepertest.New(t, map[string]string{})
	s := newLinkedStore(t, k, []config.Link{{
		Ref: "gh/token", Path: path, Type: secretlink.KindText,
	}})
	s.Reload()
	if reason := s.Unreadable(); reason != "" {
		t.Fatalf("the store refused before the keeper went away: %s", reason)
	}

	if err := k.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	s.Reload()

	if reason := s.Unreadable(); reason != "" {
		t.Errorf("a links-only store refused when the keeper went away: %s", reason)
	}
	if got, err := s.Value("gh/token"); err != nil || got != "gho_linked_example" {
		t.Errorf("value = (%q, %v), want the linked one still held", got, err)
	}
}

// The whole point of separating the two clocks. min_refresh_sec bounds the keeper
// round trip; a linked file is the operator's own and this uid can stat it, so
// it is checked every request. With them on one clock, a token another tool
// had just rotated would be missing from the redactor for up to a minute, and a
// rotation is not something the operator schedules.
func TestALinkIsPickedUpInsideTheKeeperInterval(t *testing.T) {
	path := writeLinked(t, "token", "gho_first_example\n")
	k := keepertest.New(t, map[string]string{})
	s := New(
		// An interval long enough that nothing in this test could reach it.
		config.SecretConfig{
			MinRefreshSec: 3600, MinLength: 8,
			Links: []config.Link{{Ref: "gh/token", Path: path, Type: secretlink.KindText}},
		},
		config.KeeperConfig{SocketPath: k.Path},
	)
	s.Reload()

	if err := os.WriteFile(path, []byte("gho_second_example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.RefreshIfStale()

	got, err := s.Value("gh/token")
	if err != nil {
		t.Fatal(err)
	}
	if got != "gho_second_example" {
		t.Errorf("value = %q, want the edited one: the link waited on the keeper's "+
			"interval instead of being stat'ed per request", got)
	}
}

// With the keeper unreachable, a load records no link state, so the link
// comparison cannot match. Left to itself it would call every request a
// change: a full round trip each time, and a log line saying a file changed
// when none did. The retry belongs under the interval instead.
func TestAnUnreachableKeeperDoesNotReloadOnEveryRequest(t *testing.T) {
	path := writeLinked(t, "token", "gho_linked_example\n")
	k := keepertest.New(t, map[string]string{})
	s := New(
		config.SecretConfig{
			MinRefreshSec: 3600, MinLength: 8,
			Links: []config.Link{{Ref: "gh/token", Path: path, Type: secretlink.KindText}},
		},
		config.KeeperConfig{SocketPath: k.Path},
	)
	if err := k.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	s.Reload()
	if reason := s.Unreadable(); reason == "" {
		t.Fatal("a cold start against a dead keeper served anyway")
	}

	// checkedAt moves only when the interval lets an attempt through, so it is
	// what says whether these requests each tried the keeper again.
	s.mu.RLock()
	before := s.checkedAt
	s.mu.RUnlock()
	for range 5 {
		s.RefreshIfStale()
	}
	s.mu.RLock()
	after := s.checkedAt
	s.mu.RUnlock()
	if !after.Equal(before) {
		t.Error("a request inside the interval reached the keeper again: the link " +
			"check is treating an unrecorded state as a change")
	}
}

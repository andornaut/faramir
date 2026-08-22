package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/guard"
)

// An install that declares none is the first answer a caller gets, and the one
// a configuration manager reads on every host it has not configured yet. A nil
// slice marshals to `null`, which is not a document anything can iterate: the
// list has to come back as an empty array.
func TestListingNothingIsAnEmptyArray(t *testing.T) {
	for name, run := range map[string]func() int{
		"link ls": func() int { return runLinkList(linkFlags{json: true}) },
		// --declared, which is the half a configuration manager converges. The
		// bare form carries the built-in rules, which are compiled in and are
		// never none: TestRefuseLsCarriesTheBuiltInRules.
		"block ls --declared": func() int {
			return runBlockList(blockFlags{json: true, declared: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			// A directory with no config at all, which is a host not provisioned
			// yet: Links and BlockedPaths both read that as declaring none.
			atConfigDir(t, t.TempDir())
			out, code := captureStdout(t, run)
			if code != 0 {
				t.Fatalf("exit %d, want 0: %s", code, out)
			}
			body := strings.TrimSpace(out)
			if body == "null" {
				t.Fatalf("printed null; a caller iterating the document breaks on it")
			}
			var entries []map[string]any
			if err := json.Unmarshal([]byte(body), &entries); err != nil {
				t.Fatalf("not a JSON array: %v\n%s", err, body)
			}
			if len(entries) != 0 {
				t.Errorf("got %d entries from an install declaring none", len(entries))
			}
		})
	}
}

// The listing is the whole answer to "what is blocked here": what this host
// declared, this install's own directories, and the command rules. The
// directories are the part an operator cannot otherwise ask about, being
// derived from the layout rather than written anywhere they would read.
func TestBlockLsCarriesTheInstallsOwnDirectories(t *testing.T) {
	atConfigDir(t, t.TempDir())
	out, code := captureStdout(t, func() int {
		return runBlockList(blockFlags{json: true})
	})
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
		t.Fatalf("not a JSON array: %v\n%s", err, out)
	}
	var dirs int
	for _, row := range rows {
		if row["source"] == "built-in" && row["kind"] == "path" {
			dirs++
		}
	}
	// The config directory, the store, the log and libexec at least; the three
	// service accounts' directories need installed units to be named.
	if dirs < 4 {
		t.Errorf("the listing carries %d of this install's directories, want at "+
			"least four: %v", dirs, rows)
	}
	// No pattern is compiled in, so nothing built in is a name: the built-in half
	// is this host's own paths and the commands faramir carries, and a name would
	// be a guess at a file it does not write.
	for _, row := range rows {
		if row["source"] == "built-in" && row["kind"] == "name" {
			t.Errorf("the listing carries a built-in name pattern: %v", row)
		}
	}
	// And a row is one of three kinds, whatever half it came from: a suffix and a
	// prefix are spellings of a name, and the entry shows which.
	for _, row := range rows {
		switch row["kind"] {
		case "name", "path", "command":
		default:
			t.Errorf("%v is kind %v, want one of name, path or command", row["entry"], row["kind"])
		}
	}
}

// The command rules are listed too, because nothing else can be asked what they
// are: an agent meets one as a refusal naming the rule that matched, never the
// set, which is how a rule that covers something comes to be reported as a gap.
func TestRefuseLsCarriesTheCommandRules(t *testing.T) {
	atConfigDir(t, t.TempDir())
	out, code := captureStdout(t, func() int {
		return runBlockList(blockFlags{json: true})
	})
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
		t.Fatalf("not a JSON array: %v\n%s", err, out)
	}
	var commands int
	for _, row := range rows {
		if row["kind"] != "command" {
			continue
		}
		commands++
		if row["source"] != "built-in" {
			t.Errorf("a command rule is source %v, want built-in", row["source"])
		}
	}
	if commands != len(guard.ActionPatterns()) {
		t.Errorf("listed %d command rule(s), the guard applies %d",
			commands, len(guard.ActionPatterns()))
	}
	// --declared is the config's own half, which no command rule is part of.
	out, _ = captureStdout(t, func() int {
		return runBlockList(blockFlags{json: true, declared: true})
	})
	if strings.Contains(out, `"command"`) {
		t.Errorf("--declared listed a command rule: %s", out)
	}
}

// atConfigDir points discovery at a directory for the length of one test. The
// commands no longer take one: they ask the broker and read its unit, and a
// test that did neither would report on whatever install this machine has.
// atConfigDir points the discovery ladder at an install in dir, writing the
// config file it names: a listing reports on an install, so it establishes
// there is one before saying what it holds, and a directory with no config in
// it is a host to fail on rather than one declaring nothing.
func atConfigDir(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("[secret]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARAMIR_CONFIG", path)
}

// And a config file that is not there is a refusal rather than an empty list.
// The path came from $FARAMIR_CONFIG, from the running broker or from the unit,
// so each of them asserted an install: nothing there is the wrong install or a
// broken one, and "declares nothing" is the one answer that reads as neither.
func TestAListingRefusesAnInstallThatIsNotThere(t *testing.T) {
	for name, run := range map[string]func() int{
		"link ls":             func() int { return runLinkList(linkFlags{json: true}) },
		"block ls":            func() int { return runBlockList(blockFlags{json: true}) },
		"block ls --declared": func() int { return runBlockList(blockFlags{json: true, declared: true}) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("FARAMIR_CONFIG", filepath.Join(t.TempDir(), "config.toml"))
			out, code := captureStdout(t, run)
			if code == 0 {
				t.Errorf("exit 0 against a config that is not there: %s", out)
			}
		})
	}
}

// The two halves of the listing, each on its own, and together making the whole
// of it. A caller converging the config reads --declared; one asking what this
// install refuses without being told to reads --built-in, which is the half no
// entry names and no `block rm` removes.
func TestTheTwoHalvesOfBlockLsPartitionIt(t *testing.T) {
	atConfigDir(t, t.TempDir())
	count := func(f blockFlags) int {
		t.Helper()
		f.json = true
		out, code := captureStdout(t, func() int { return runBlockList(f) })
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
			t.Fatalf("not a JSON array: %v\n%s", err, out)
		}
		return len(rows)
	}
	both := count(blockFlags{})
	declared := count(blockFlags{declared: true})
	builtIn := count(blockFlags{builtIn: true})
	if declared+builtIn != both {
		t.Errorf("%d declared + %d built-in = %d, but the whole listing is %d",
			declared, builtIn, declared+builtIn, both)
	}
	if builtIn == 0 {
		t.Error("--built-in listed nothing; the layout always renders some")
	}
}

// Naming both narrows to everything, which is the default, so a caller that
// wrote both meant one of them.
func TestNamingBothHalvesIsRefused(t *testing.T) {
	atConfigDir(t, t.TempDir())
	out, code := captureStdout(t, func() int {
		return runBlockList(blockFlags{declared: true, builtIn: true})
	})
	if code != 2 {
		t.Errorf("exit %d, want 2: %s", code, out)
	}
}

// --built-in reports only rows nothing declared, whatever the config carries.
func TestBuiltInLeavesTheDeclaredEntriesOut(t *testing.T) {
	atConfigDir(t, t.TempDir())
	out, code := captureStdout(t, func() int {
		return runBlockList(blockFlags{json: true, builtIn: true})
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row["source"] != "built-in" {
			t.Errorf("--built-in listed a %v row: %v", row["source"], row)
		}
	}
}

// A listing is read twice and diffed between hosts, so its order is the entry's
// rather than the order it happened to be declared in. Within a half, not
// across one: the declared entries come first because that is the half an
// operator wrote and a configuration manager converges.
func TestTheListingIsSortedWithinEachHalf(t *testing.T) {
	// Written out of order, and mixing the three kinds, so the half is sorted by
	// this rather than by the order it was declared in. A fixture with no
	// declared entries would leave that half empty and pass whatever the code
	// does.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(`[secret]
[[secret.block]]
path = "/srv/zulu.key"
[[secret.block]]
name = "id_rsa"
[[secret.block]]
command = "pass show"
[[secret.block]]
path = "/srv/alpha.key"
[[secret.block]]
name = "*.pem"
[[secret.block]]
command = "op read"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARAMIR_CONFIG", filepath.Join(dir, "config.toml"))
	out, code := captureStdout(t, func() int { return runBlockList(blockFlags{json: true}) })
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	var rows []blockRow
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
		t.Fatal(err)
	}
	for _, half := range []string{sourceDeclared, sourceBuiltIn} {
		var keys []string
		for _, r := range rows {
			if r.Source == half {
				keys = append(keys, r.Kind+"\x00"+r.Entry)
			}
		}
		if len(keys) < 2 {
			t.Errorf("the %s half has %d row(s), too few to be an order", half, len(keys))
		}
		if !slices.IsSorted(keys) {
			t.Errorf("the %s half is not sorted by kind then entry: %v", half, keys)
		}
	}
	// And no declared row appears after a built-in one.
	seenBuiltIn := false
	for _, r := range rows {
		if r.Source == sourceBuiltIn {
			seenBuiltIn = true
		} else if seenBuiltIn {
			t.Errorf("a declared row follows a built-in one: %+v", r)
		}
	}
}

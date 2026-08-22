package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/guard"
)

// An install that declares none is the first answer a caller gets, and the one
// a configuration manager reads on every host it has not configured yet. A nil
// slice marshals to `null`, which is not a document anything can iterate: the
// list has to come back as an empty array.
func TestListingNothingIsAnEmptyArray(t *testing.T) {
	for name, run := range map[string]func(string) int{
		"link ls": func(dir string) int { return runLinkList(linkFlags{json: true, configPath: dir}) },
		// --declared, which is the half a configuration manager converges. The
		// bare form carries the built-in rules, which are compiled in and are
		// never none: TestRefuseLsCarriesTheBuiltInRules.
		"block ls --declared": func(dir string) int {
			return runBlockList(blockFlags{json: true, declared: true, configPath: dir})
		},
	} {
		t.Run(name, func(t *testing.T) {
			// A directory with no config at all, which is a host not provisioned
			// yet: Links and BlockedPaths both read that as declaring none.
			out, code := captureStdout(t, func() int { return run(t.TempDir()) })
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
	out, code := captureStdout(t, func() int {
		return runBlockList(blockFlags{json: true, configPath: t.TempDir()})
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
		if row["source"] != "built-in" || row["kind"] != "dir" {
			continue
		}
		dirs++
		if row["covers"] != "file tools, commands" {
			t.Errorf("%v covers %v, want both entry points", row["entry"], row["covers"])
		}
	}
	// The config directory, the store, the log and libexec at least; the three
	// service accounts' directories need installed units to be named.
	if dirs < 4 {
		t.Errorf("the listing carries %d of this install's directories, want at "+
			"least four: %v", dirs, rows)
	}
	// No pattern is compiled in, so nothing built in is a name or a suffix.
	for _, row := range rows {
		if row["source"] == "built-in" && row["kind"] != "command" && row["kind"] != "dir" {
			t.Errorf("the listing carries a built-in pattern: %v", row)
		}
	}
}

// The command rules are listed too, because nothing else can be asked what they
// are: an agent meets one as a refusal naming the rule that matched, never the
// set, which is how a rule that covers something comes to be reported as a gap.
func TestRefuseLsCarriesTheCommandRules(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return runBlockList(blockFlags{json: true, configPath: t.TempDir()})
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
		if row["covers"] != "commands" {
			t.Errorf("a command rule covers %v, want commands", row["covers"])
		}
	}
	if commands != len(guard.ActionPatterns()) {
		t.Errorf("listed %d command rule(s), the guard applies %d",
			commands, len(guard.ActionPatterns()))
	}
	// --declared is the config's own half, which no command rule is part of.
	out, _ = captureStdout(t, func() int {
		return runBlockList(blockFlags{json: true, declared: true, configPath: t.TempDir()})
	})
	if strings.Contains(out, `"command"`) {
		t.Errorf("--declared listed a command rule: %s", out)
	}
}

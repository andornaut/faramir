package main

import (
	"encoding/json"
	"strings"
	"testing"
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
		"refuse ls --declared": func(dir string) int {
			return runRefuseList(refuseFlags{json: true, declared: true, configPath: dir})
		},
	} {
		t.Run(name, func(t *testing.T) {
			// A directory with no config at all, which is a host not provisioned
			// yet: Links and RefusedPaths both read that as declaring none.
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

// The built-in rules are otherwise unaskable: an agent meets one as a file tool
// refusing a path, and the refusal names the rule that matched rather than the
// set, so a gap can be reported that was never open. A host with no config at
// all still answers, the list being compiled in.
func TestRefuseLsCarriesTheBuiltInRules(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return runRefuseList(refuseFlags{json: true, configPath: t.TempDir()})
	})
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
		t.Fatalf("not a JSON array: %v\n%s", err, out)
	}
	want := map[string]string{
		"age.key":          "name",
		".sops.yml":        "suffix",
		"sops/age/":        "dir",
		".config/faramir/": "dir",
	}
	for entry, kind := range want {
		found := false
		for _, row := range rows {
			if row["entry"] == entry {
				found = true
				if row["kind"] != kind {
					t.Errorf("%s is kind %v, want %s", entry, row["kind"], kind)
				}
				if row["source"] != "built-in" {
					t.Errorf("%s is source %v, want built-in", entry, row["source"])
				}
			}
		}
		if !found {
			t.Errorf("the listing does not carry the built-in rule %q", entry)
		}
	}
}

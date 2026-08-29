package guard

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"testing"
)

// codexPayloads is what Codex actually sends, captured from codex-cli 0.151.0
// rather than written here. Every other Codex test builds its own payload, so
// they all agree with the code because one assumption wrote both; this is the
// only thing in the package that would notice the contract being wrong.
//
// The capture is verbatim but for the absolute paths, which were the operator's
// and are rewritten to /srv/project and /home/operator. The relative header
// paths are untouched, being relative already and carrying nothing of the host.
// What is under test is the field names, their spellings and their types, and
// none of those were touched.
//
// It is good for the version named and for nothing else. A Codex release may
// rename a tool or move the envelope, and the failure that would cause is
// silent in one direction: a shell tool under another name makes commandOf
// non-empty, skips the path branch, fails handles(), and allows every command
// unrouted. So a version bump means capturing again, not editing this to pass.
const codexPayloads = "testdata/codex-payloads.jsonl"

// Codex may have other tools that carry a path. None of them were exercised, so
// this asserts what was seen and claims nothing about a reader, a search or a
// fetch. What was seen is a shell call and all four patch verbs.
//
// The header paths are a mix of absolute and relative on purpose, and that is
// observed rather than untidy: the same agent at the same version emitted
// `Add File:` absolute and `Update File:`, `Delete File:` and `Move to:`
// relative. Normalising either way would delete the evidence. It is also what
// makes resolving a header against the payload's cwd load-bearing rather than
// tidy: a relative header asked as written matches no rule spelled absolutely,
// so `*** Delete File: ../.config/faramir/<file>` from a tree beside the config
// is the shape that would otherwise go through.
func TestTheCodexContractMatchesACapturedPayload(t *testing.T) {
	fh, err := os.Open(codexPayloads)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()

	seen := map[string]bool{}
	var patches strings.Builder
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parsed, err := decodeToolInput([]byte(line))
		if err != nil {
			t.Fatalf("a real Codex payload does not decode, so every call would be "+
				"denied as unreadable: %v", err)
		}
		p := *parsed
		seen[p.ToolName] = true
		if p.ToolName == hosts["codex"].patchTool {
			patches.WriteString(p.ToolInput.Command + "\n")
		}
		// The envelope is where the guard reads it. Empty here would mean the
		// patch branch allowing every write and the shell branch checking nothing.
		if p.ToolInput.Command == "" {
			t.Errorf("%s: tool_input.command is empty, so the guard reads the "+
				"envelope from somewhere Codex does not put it", p.ToolName)
		}
		if p.Cwd == "" {
			t.Errorf("%s: no cwd, so a relative path is a guess rather than resolved",
				p.ToolName)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	host := hosts["codex"]
	if !seen[bashTool] {
		t.Errorf("the capture carries no %q call, so nothing here says the shell "+
			"tool is spelled the way host.go matches it", bashTool)
	}
	if !seen[host.patchTool] {
		t.Errorf("the capture carries no %q call, so nothing here says the patch "+
			"tool is spelled the way host.go matches it", host.patchTool)
	}
	// Every verb the guard reads a path off. One missing means a rename or a
	// deletion going unchecked, which is the half of the branch nothing else
	// would report.
	for _, verb := range []string{"Add File:", "Update File:", "Delete File:", "Move to:"} {
		if !strings.Contains(patches.String(), verb) {
			t.Errorf("no captured patch carries %q, so nothing observed says that "+
				"header is spelled the way patchHeaders reads it", verb)
		}
	}
	// Both spellings, which is what the cwd resolution is for. Losing either
	// leaves that resolution asserted by nothing real.
	if !strings.Contains(patches.String(), ": /") {
		t.Error("no captured header names an absolute path")
	}
	if !relativeHeader.MatchString(patches.String()) {
		t.Error("no captured header names a relative path, so nothing here holds " +
			"the cwd resolution to a shape Codex actually emits")
	}
}

// A header whose path does not start with a separator. Anchored per line, the
// envelope being one string carrying several.
var relativeHeader = regexp.MustCompile(`(?m)^\*\*\* (?:Add File|Update File|Delete File|Move to): [^/\n]`)

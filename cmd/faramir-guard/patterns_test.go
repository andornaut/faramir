package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const shippedPatterns = "../../agent/hooks/deny-patterns.txt"

func shippedLines(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(shippedPatterns)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// Every shipped pattern must compile under RE2.  Python's `re` accepts
// lookahead and backreferences; Go's regexp does not, and a pattern that fails
// to compile is skipped at load, silently weakening the list.  This is the
// exact failure mode the port could introduce, so it is asserted rather than
// assumed.
func TestEveryShippedPatternCompilesUnderRE2(t *testing.T) {
	lines := shippedLines(t)
	if len(lines) == 0 {
		t.Fatal("no patterns in the shipped file")
	}
	for _, pattern := range lines {
		if _, err := regexp.Compile("(?i)" + pattern); err != nil {
			t.Errorf("shipped pattern does not compile under RE2: %q: %v", pattern, err)
		}
	}
}

// The shipped file and the built-in fallback have to agree.  A fallback weaker
// than the shipped list turns an install problem into a silent gap.
func TestTheFallbackMatchesTheShippedFile(t *testing.T) {
	shipped := shippedLines(t)
	if len(shipped) != len(fallback) {
		t.Fatalf("shipped file has %d patterns, fallback has %d", len(shipped), len(fallback))
	}
	for i := range shipped {
		if shipped[i] != fallback[i] {
			t.Errorf("pattern %d differs:\n  shipped:  %s\n  fallback: %s", i, shipped[i], fallback[i])
		}
	}
}

// The shipped file must actually deny the things it exists to deny, loaded from
// disk rather than from the fallback.
func TestTheShippedFileDeniesTheDocumentedCases(t *testing.T) {
	abs, err := filepath.Abs(shippedPatterns)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARAMIR_DENY_PATTERNS", abs)

	for _, cmd := range []string{"printenv", "env", "sops -d x.sops.yml", "age-keygen"} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("shipped file did not deny %q", cmd)
		}
	}
	if _, denied := decide("env | grep PATH"); denied {
		t.Error("shipped file denied a piped env")
	}
}

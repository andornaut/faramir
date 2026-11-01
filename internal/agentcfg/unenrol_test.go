package agentcfg

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnenrolConfigKeepsUnrelatedSettingsAndPermissions(t *testing.T) {
	current := []byte(`{"large":9007199254740993,"permissions":{"deny":["Read(keep)"]},"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"command":"/usr/local/bin/faramir guard"},{"command":"/opt/keep-hook"}]}]}}`)
	out, err := WithoutProjectConfig(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"9007199254740993", "Read(keep)", "/opt/keep-hook", `"matcher": "*"`} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("lost %q in %s", want, out)
		}
	}
	if bytes.Contains(out, []byte("faramir guard")) {
		t.Fatalf("routing remains: %s", out)
	}
	twice, err := WithoutProjectConfig(out)
	if err != nil || !bytes.Equal(out, twice) {
		t.Fatalf("cleanup is not idempotent: %s, %v", twice, err)
	}
}

func TestUnenrolConfigRejectsMalformedJSON(t *testing.T) {
	for _, current := range []string{`{`, `null`, `[]`, `{} {}`, `{"hooks":[]}`, `{"hooks":{"PreToolUse":{}}}`} {
		if _, err := WithoutProjectConfig([]byte(current)); err == nil {
			t.Errorf("accepted %s", current)
		}
	}
}

func TestUnenrolSectionPreservesOutsideBytesAndRejectsAmbiguousMarkers(t *testing.T) {
	block := SectionBegin + "\nmanaged\n" + SectionEnd
	current := "before\n\n" + block + "\n\nafter\n"
	out, err := WithoutProjectSection([]byte(current))
	if err != nil || string(out) != "before\n\n\n\nafter\n" {
		t.Fatalf("outside bytes changed: %q, %v", out, err)
	}
	for _, current := range []string{SectionBegin, SectionEnd, SectionEnd + SectionBegin, block + block, "# Credentials\nfaramir run"} {
		if _, err := WithoutProjectSection([]byte(current)); err == nil {
			t.Errorf("accepted ambiguous section %s", current)
		}
	}
	plain := "# Project\n\nOperator text.\n"
	out, err = WithoutProjectSection([]byte(plain))
	if err != nil || strings.TrimSpace(string(out)) != strings.TrimSpace(plain) {
		t.Fatalf("changed plain prose: %q, %v", out, err)
	}
}

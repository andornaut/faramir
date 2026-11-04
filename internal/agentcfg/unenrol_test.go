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

// The key removed is the key the asset writes, so the two cannot drift apart.
func TestAntigravityHookRemovalTakesWhatTheAssetWrites(t *testing.T) {
	target := Targets["antigravity"]
	var hook File
	for _, file := range target.AccountFiles {
		if file.Path == antigravityAccountHooks {
			hook = file
		}
	}
	if hook.Without == nil {
		t.Fatalf("%s has no cleanup of its own", antigravityAccountHooks)
	}
	written, err := RenderData(hook.Asset, PluginData{BinDir: "/usr/local/bin", Agent: target.Name, Family: target.FamilyName()})
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeJSON([]byte(`{"mine":{"enabled":true,"keep":"operator"}}`), written, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := hook.Without(merged)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("faramir")) || !bytes.Contains(out, []byte(`"keep": "operator"`)) {
		t.Fatalf("after removal: %s", out)
	}
	twice, err := hook.Without(out)
	if err != nil || !bytes.Equal(out, twice) {
		t.Fatalf("removal is not idempotent: %s, %v", twice, err)
	}
	// Nothing else in the file: it stays, as the agent's own.
	alone, err := hook.Without(written)
	if err != nil || string(alone) != "{}\n" {
		t.Fatalf("a file holding only the hook = %q, %v; want {}", alone, err)
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

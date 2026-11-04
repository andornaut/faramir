package enrol

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
)

const (
	homePlugin    = ".config/opencode/plugin/faramir.js"
	homeExtension = ".pi/agent/extensions/faramir.ts"
)

func unenrolHomeFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	writeUnenrolFile(t, home, homePlugin, "export const FaramirPlugin = async () => ({})\n")
	// A dotfiles manager's link: the link goes, the file it names stays.
	writeUnenrolFile(t, home, "dotfiles/faramir.ts", "export default () => {}\n")
	if err := os.MkdirAll(filepath.Join(home, filepath.Dir(homeExtension)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "dotfiles/faramir.ts"), filepath.Join(home, homeExtension)); err != nil {
		t.Fatal(err)
	}
	writeUnenrolFile(t, home, ".claude/settings.json",
		`{"permissions":{"deny":["Read(//home/op/.ssh/**)"]},"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"command":"/usr/local/bin/faramir guard --deny-only"},{"command":"/opt/user-hook"}]}]}}`)
	writeUnenrolFile(t, home, ".claude/CLAUDE.md",
		"# Mine\n\nUser prose.\n\n"+agentcfg.SectionBegin+"\nmanaged\n"+agentcfg.SectionEnd+"\n")
	writeUnenrolFile(t, home, agentcfg.CodexHooksFile,
		`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"command":"/usr/local/bin/faramir guard --host codex --deny-only"}]}]}}`)
	return home
}

func TestUnenrolHomeRemovesHooksPluginsAndSection(t *testing.T) {
	home := unenrolHomeFixture(t)
	report, err := UnenrolHome(os.Getuid(), home)
	if err != nil || !report.Changed {
		t.Fatalf("UnenrolHome = %+v, %v", report, err)
	}
	for _, rel := range []string{homePlugin, homeExtension} {
		if _, err := os.Lstat(filepath.Join(home, rel)); !os.IsNotExist(err) {
			t.Errorf("%s survived: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "dotfiles/faramir.ts")); err != nil {
		t.Errorf("removing the link removed what it named: %v", err)
	}
	for _, rel := range []string{".claude/settings.json", ".claude/CLAUDE.md", agentcfg.CodexHooksFile} {
		if body := readUnenrolFile(t, home, rel); bytes.Contains(body, []byte("faramir")) {
			t.Errorf("faramir's content remains in %s: %s", rel, body)
		}
	}
	settings := readUnenrolFile(t, home, ".claude/settings.json")
	if !bytes.Contains(settings, []byte("Read(//home/op/.ssh/**)")) || !bytes.Contains(settings, []byte("/opt/user-hook")) {
		t.Errorf("lost the operator's configuration: %s", settings)
	}
	if body := readUnenrolFile(t, home, ".claude/CLAUDE.md"); string(body) != "# Mine\n\nUser prose.\n\n\n" {
		t.Errorf("CLAUDE.md = %q", body)
	}
	again, err := UnenrolHome(os.Getuid(), home)
	if err != nil || again.Changed {
		t.Errorf("a second run = %+v, %v; want nothing changed", again, err)
	}
}

// A merged file that cannot be stripped is an error naming it, and does not
// keep the plugins in place: they fail closed once the binary is gone.
func TestUnenrolHomeRemovesPluginsWhenAnEditFails(t *testing.T) {
	home := unenrolHomeFixture(t)
	writeUnenrolFile(t, home, ".config/kilo/kilo.json", "{ not json")
	_, err := UnenrolHome(os.Getuid(), home)
	if err == nil || !strings.Contains(err.Error(), ".config/kilo/kilo.json") {
		t.Fatalf("err = %v, want one naming the unparseable file", err)
	}
	if _, err := os.Lstat(filepath.Join(home, homePlugin)); !os.IsNotExist(err) {
		t.Errorf("the plugin survived a failed edit elsewhere: %v", err)
	}
	if body := readUnenrolFile(t, home, ".claude/settings.json"); !bytes.Contains(body, []byte("faramir guard")) {
		t.Errorf("an edit was written although preparing another failed: %s", body)
	}
}

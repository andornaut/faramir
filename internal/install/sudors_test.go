package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeVisudo writes a program that answers -V with the line given, and fails
// every other invocation the way a visudo rejecting a file does.
func fakeVisudo(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "visudo")
	script := "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then printf '%s\\n' " +
		"'" + version + "'; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// A refusal has to name the thing that caused it. sudo-rs rejects pam_service
// as an unknown setting and takes the whole entry down with it, so visudo's own
// message reads as a typo in a directive faramir wrote deliberately.
func TestARejectedGrantNamesSudoRs(t *testing.T) {
	note := sudoRsNote(fakeVisudo(t, "sudo-rs 0.2.13"))
	if note == "" {
		t.Fatal("a grant rejected by sudo-rs said nothing about sudo-rs")
	}
	for _, want := range []string{"sudo-rs", "pam_service", "--allow-sudo"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note does not name %q: %s", want, note)
		}
	}
}

// And says nothing where classic sudo rejected it, the cause then being the
// grant itself or something else in sudoers.d, which visudo's own message
// covers. A note on every rejection would send operators after the wrong thing.
func TestARejectedGrantIsSilentAboutClassicSudo(t *testing.T) {
	for _, version := range []string{
		"Sudo version 1.9.15p5\nSudoers policy plugin version 1.9.15p5",
		"Sudo version 1.9.17p2",
	} {
		if note := sudoRsNote(fakeVisudo(t, version)); note != "" {
			t.Errorf("classic sudo %q drew a sudo-rs note: %s", version, note)
		}
	}
}

// A visudo that cannot be asked its version says nothing rather than guessing.
// The rejection is reported either way; this only adds a cause.
func TestAVisudoThatWillNotReportItsVersionAddsNothing(t *testing.T) {
	if note := sudoRsNote(filepath.Join(t.TempDir(), "not-there")); note != "" {
		t.Errorf("an unreadable visudo drew a note: %s", note)
	}
}

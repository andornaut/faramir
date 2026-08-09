package sshkey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regenerating a key locks the broker out of every host its public half is on,
// with a key file that looks healthy, so a second run reports what it found and
// writes nothing.
func TestGenerateNeverClobbersAnExistingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")

	first, created, err := Generate(path, "faramir-broker@host")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("the first call reported the file was already there")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	second, created, err := Generate(path, "faramir-broker@host")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("a second call reported that it minted a key")
	}
	if second != first {
		t.Errorf("public half = %q, want the existing %q", second, first)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("THE PRIVATE KEY WAS REWRITTEN: every authorized_keys holding the old one is stale")
	}
}

// Two halves, two modes, both from the write rather than the umask.  0600 keeps
// the private half to the broker's uid; 0644 on the public half is deliberate,
// it being copied into authorized_keys on every managed host.
func TestGenerateWritesBothModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if _, _, err := Generate(path, "faramir-broker@host"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		path string
		want os.FileMode
	}{
		{"the private half", path, 0o600},
		{"the public half", path + ".pub", 0o644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := os.Stat(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != tc.want {
				t.Errorf("mode is %o, want %o", got, tc.want)
			}
		})
	}
}

// What the caller is handed is printed by init and pasted into a ticket.
func TestTheReturnedLineCarriesNoPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	public, _, err := Generate(path, "faramir-broker@host")
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(public, "PRIVATE KEY") {
		t.Errorf("KEY MATERIAL RETURNED: %q", public)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(private)), "\n") {
		if len(line) > 20 && strings.Contains(public, line) {
			t.Errorf("the returned line quotes the private key: %q", line)
		}
	}
}

// The returned line is what gets pasted into authorized_keys, so it has to be
// one line: a type, a key, a comment, and no newline to lose in the paste.
func TestTheAuthorizedKeyLineIsCompleteAndCarriesTheComment(t *testing.T) {
	const comment = "faramir-broker@host"
	path := filepath.Join(t.TempDir(), "id_ed25519")
	public, _, err := Generate(path, comment)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(public, "\n") {
		t.Errorf("the returned line carries a newline: %q", public)
	}
	fields := strings.Fields(public)
	if len(fields) != 3 {
		t.Fatalf("public = %q, want three fields", public)
	}
	if fields[0] != "ssh-ed25519" {
		t.Errorf("key type = %q, want ssh-ed25519", fields[0])
	}
	if fields[2] != comment {
		t.Errorf("comment = %q, want %q", fields[2], comment)
	}

	// The same line, being the copy an operator reaches for later.
	onDisk, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(onDisk)) != public {
		t.Errorf(".pub holds %q, want %q", strings.TrimSpace(string(onDisk)), public)
	}
}

// Public reads the line back, which is what a second run does.
func TestPublicReadsTheLineBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	public, _, err := Generate(path, "faramir-broker@host")
	if err != nil {
		t.Fatal(err)
	}
	read, err := Public(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if read != public {
		t.Errorf("Public = %q, want %q", read, public)
	}
}

// An error rather than a line the operator would paste into authorized_keys.
func TestPublicRefusesSomethingElse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519.pub")
	if err := os.WriteFile(path, []byte("not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Public(path); err == nil {
		t.Error("a file that is not a public key was accepted")
	}
}

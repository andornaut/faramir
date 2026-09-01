package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	sops "github.com/getsops/sops/v3"

	"github.com/andornaut/faramir/internal/sopstest"
)

// useSops points the edit path at the host's sops, or the stand-in. A full
// decrypt, edit and re-encrypt either way.
func useSops(t *testing.T) {
	t.Helper()
	previous := SopsBinary
	SopsBinary = sopstest.SopsBinary(t)
	t.Cleanup(func() { SopsBinary = previous })
}

// editorScript writes a shell script standing in for the editor.
func editorScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "editor")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func encryptedFixture(t *testing.T) (store, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	keyPath, recipient := sopstest.NewIdentity(t, dir)
	store = filepath.Join(dir, "store.sops.yml")
	sopstest.WriteEncrypted(t, store, recipient, sops.TreeBranch{
		{Key: "secret_one", Value: "the-original-value-long-enough"},
	})
	return store, keyPath
}

func TestAnEditIsDecryptedEditedAndReEncrypted(t *testing.T) {
	useSops(t)
	store, keyPath := encryptedFixture(t)

	before, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}

	editor := editorScript(t, `sed -i 's/the-original-value-long-enough/a-replacement-value-long-enough/' "$1"`)
	changed, err := Edit(keyPath, "", editor, store)
	if err != nil {
		t.Fatalf("editManaged: %v", err)
	}
	if !changed {
		t.Fatal("reported no change after the editor rewrote the plaintext")
	}

	after, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	// Still ciphertext, and not the bytes it started as.
	if string(after) == string(before) {
		t.Error("the secrets directory was not rewritten")
	}
	if strings.Contains(string(after), "a-replacement-value-long-enough") {
		t.Fatal("the new value is in the file as plaintext")
	}
	if !strings.Contains(string(after), "sops") {
		t.Error("the rewritten file does not look like a sops file")
	}

	// And it decrypts to what the editor wrote.
	plain, err := RunSops(keyPath, "", "--decrypt", store)
	if err != nil {
		t.Fatalf("decrypting the result: %v", err)
	}
	if !strings.Contains(string(plain), "a-replacement-value-long-enough") {
		t.Errorf("the edit did not survive the round trip: %s", plain)
	}
}

// Re-encrypting rewrites the data key, so a no-op edit would look like a change
// to anything watching the file.
func TestAnUnchangedEditRewritesNothing(t *testing.T) {
	useSops(t)
	store, keyPath := encryptedFixture(t)

	before, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := Edit(keyPath, "", editorScript(t, "true"), store)
	if err != nil {
		t.Fatalf("editManaged: %v", err)
	}
	if changed {
		t.Error("reported a change when the editor wrote nothing")
	}
	after, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("the secrets directory was rewritten by an edit that changed nothing")
	}
}

// Writing back what an editor abandoned would replace a good file with a
// partial one.
func TestAFailedEditorLeavesTheStoreAlone(t *testing.T) {
	useSops(t)
	store, keyPath := encryptedFixture(t)

	before, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Edit(keyPath, "", editorScript(t, "exit 1"), store); err == nil {
		t.Error("an editor that failed was reported as a successful edit")
	}
	after, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("the secrets directory changed after the editor failed")
	}
}

// The mode the file had is the mode it keeps: an install hands the secrets
// directory to the secrets group, and the umask must not undo that.
func TestTheReplacementKeepsTheOriginalMode(t *testing.T) {
	useSops(t)
	store, keyPath := encryptedFixture(t)
	if err := os.Chmod(store, 0o640); err != nil {
		t.Fatal(err)
	}

	editor := editorScript(t, `sed -i 's/the-original-value-long-enough/another-value-long-enough-here/' "$1"`)
	if _, err := Edit(keyPath, "", editor, store); err != nil {
		t.Fatalf("editManaged: %v", err)
	}
	info, err := os.Stat(store)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("mode after the edit is %o, want 640", got)
	}
}

// The plaintext lives in a tmpfs directory nothing else can enter, and is gone
// once the edit returns.
func TestThePlaintextIsRemovedAndWasNotOnDisk(t *testing.T) {
	useSops(t)
	store, keyPath := encryptedFixture(t)

	recorded := filepath.Join(t.TempDir(), "where")
	editor := editorScript(t, `printf '%s' "$1" > `+recorded+`
sed -i 's/the-original-value-long-enough/yet-another-value-long-enough/' "$1"`)
	if _, err := Edit(keyPath, "", editor, store); err != nil {
		t.Fatalf("editManaged: %v", err)
	}
	where, err := os.ReadFile(recorded)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(where), "/dev/shm/") {
		t.Errorf("the plaintext was at %s, which is not a tmpfs", where)
	}
	if _, err := os.Stat(string(where)); !os.IsNotExist(err) {
		t.Errorf("the plaintext at %s outlived the edit", where)
	}
}

package agekey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// The identity this package writes is the only thing that opens the managed
// store, and it has no backup that is not the same disk.  So the tests here are
// about the two ways a run could destroy one: writing over it, and leaving it
// readable by an account that has no business decrypting.

// Overwriting an identity revokes access to every value it was a recipient for,
// retroactively and silently: the ciphertext is still there and no longer
// opens.  A second run has to report the recipient it found and write nothing.
func TestGenerateNeverClobbersAnExistingIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "age.key")

	first, created, err := Generate(path)
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

	second, created, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("a second call reported that it minted a key")
	}
	if second != first {
		t.Errorf("recipient = %q, want the existing %q", second, first)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("THE IDENTITY WAS REWRITTEN: every value encrypted to the old one is lost")
	}
}

// 0400, set by the open rather than left to the umask: the keeper's uid reads
// it and nothing ever writes it again, and a mode that came from the umask
// would depend on the shell the install was run from.
func TestGenerateWritesTheKeyReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "age.key")
	if _, _, err := Generate(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o400 {
		t.Errorf("mode is %o, want 400", got)
	}
}

// A directory that is not there is an error rather than a key written nowhere:
// init creates the config directory first, and a Generate that reported success
// against a missing one would leave the keeper with no key and the report
// saying it had made one.
func TestGenerateReportsAnUnwritablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "age.key")
	if _, created, err := Generate(path); err == nil {
		t.Errorf("Generate reported created=%v and no error for %s", created, path)
	}
}

// What Generate returns is what Recipient reads back, which is the whole
// contract between minting a key and writing it into the sops creation rule.
func TestTheRecipientReadsBackFromTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "age.key")
	minted, _, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	read, err := Recipient(path)
	if err != nil {
		t.Fatal(err)
	}
	if read != minted {
		t.Errorf("Recipient = %q, want the minted %q", read, minted)
	}
	if !strings.HasPrefix(read, "age1") {
		t.Errorf("recipient %q is not an age recipient", read)
	}
}

// The private half must not come back as the public one.  They sit in the same
// file, and a pattern that matched the identity line would put key material
// into the .sops.yaml that install writes and doctor prints.
func TestRecipientReturnsThePublicHalfOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "age.key")
	if _, _, err := Generate(path); err != nil {
		t.Fatal(err)
	}
	read, err := Recipient(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read, "AGE-SECRET-KEY") {
		t.Errorf("KEY MATERIAL RETURNED AS A RECIPIENT: %q", read)
	}
}

// The last match wins, so a file that has accumulated more than one entry
// resolves to one answer deterministically rather than to whichever line
// happened to come first.
func TestRecipientTakesTheLast(t *testing.T) {
	first, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	second, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(path, []byte(Format(first)+Format(second)), 0o400); err != nil {
		t.Fatal(err)
	}

	read, err := Recipient(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := second.Recipient().String(); read != want {
		t.Errorf("Recipient = %q, want the last entry %q", read, want)
	}
}

// A file with nothing in it that looks like a key is named, not reported as an
// empty recipient: an empty recipient reaches the sops creation rule as a rule
// addressed to nobody.
func TestRecipientNamesAFileWithNoKeyInIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("# nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Recipient(path)
	if err == nil {
		t.Fatal("a file holding no recipient was accepted")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file: %v", err)
	}
}

// What ends up in .sops.yaml is written once and kept, and that file is 0644 by
// design: it holds public keys and a rule and no value, so checking who can
// decrypt does not need sudo.  Everything below is a string that must never
// reach it, or one that must.
func TestValidateRecipient(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		recipient string
		ok        bool
		says      string
	}{
		{name: "a minted recipient", recipient: id.Recipient().String(), ok: true},
		{
			name: "an ssh public key", ok: true,
			recipient: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7mQ0TawUvfWHLeaoBg0q1So2tY3VIpiGMzBGsDbOZi operator@host",
		},
		{
			// Accepted on its shape: only the plugin binary can parse one, and
			// requiring it on the host being provisioned would refuse a recipient
			// sops itself would take.
			name: "an age plugin recipient", ok: true,
			recipient: "age1yubikey1q2c94wdful8xa9dqe4qy5ldu2s6ct2zkweqhq5c2f3sk6zmr5rqvqm2dxqz",
		},
		{
			// The one that matters.  Both halves sit in the same file, adjacent,
			// and only one of them is safe to publish.
			name: "the private half", recipient: id.String(),
			says: "private half",
		},
		{
			name: "a path to a key file", recipient: "/home/operator/.age/key.txt",
			says: "unknown recipient type",
		},
		{
			name: "a mistyped recipient", recipient: id.Recipient().String() + "x",
			says: "not an age recipient",
		},
		{
			// A recipient is written as one item of a YAML list, so a line break
			// in it is whatever follows read as YAML of its own.
			name:      "a recipient carrying a line break",
			recipient: id.Recipient().String() + "\n          - " + id.String(),
			says:      "line break",
		},
		{name: "nothing at all", recipient: "", says: "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRecipient(tc.recipient)
			if tc.ok {
				if err != nil {
					t.Fatalf("ValidateRecipient(%q) = %v, want it accepted", tc.recipient, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateRecipient(%q) = nil: it would be written to a "+
					"world-readable file and kept there", tc.recipient)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error does not say %q: %v", tc.says, err)
			}
		})
	}
}

// The message for a private half must not quote it.  Errors are printed, logged
// and pasted into issues, and a refusal that repeats the key back has published
// it in every one of those places.
func TestValidateRecipientDoesNotEchoAPrivateKey(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateRecipient(id.String())
	if err == nil {
		t.Fatal("a private key was accepted as a recipient")
	}
	if strings.Contains(err.Error(), "AGE-SECRET-KEY") {
		t.Errorf("KEY MATERIAL IN THE ERROR: %v", err)
	}
}

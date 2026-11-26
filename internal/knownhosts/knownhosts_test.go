package knownhosts

// Counting and reading a known_hosts file.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func publicBlob(algorithm string, body []byte) string {
	return base64.StdEncoding.EncodeToString(ssh.Marshal(struct {
		Algorithm string
		Body      []byte `ssh:"rest"`
	}{algorithm, body}))
}

func ed25519Blob() string {
	return publicBlob("ssh-ed25519", ssh.Marshal(struct{ Key []byte }{make([]byte, 32)}))
}

// ssh reads a known_hosts file line by line and ignores what it cannot parse, so
// counting what it would take means counting past a bad line rather than
// rejecting the file: one hand edit in a file of two hundred must not be
// reported as a host that verifies nothing.
func TestCountKnownHostsCountsPastALineItCannotParse(t *testing.T) {
	key := "ssh-ed25519 " + ed25519Blob()
	dir := t.TempDir()
	mixed := filepath.Join(dir, "mixed")
	body := "one.example.com " + key + "\nbroken.example.com ssh-ed25519 !!!!\ntwo.example.com " + key + "\n"
	if err := os.WriteFile(mixed, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := Count(mixed); got != 2 {
		t.Errorf("Count = %d, want 2: the entries either side of a bad line "+
			"still verify their hosts", got)
	}
	// The strict read is a different question, asked of a path the operator named
	// before it is copied, and it still refuses the same file.
	if _, _, err := Read(mixed); err == nil {
		t.Error("--known-hosts accepted a file with a line it could not parse")
	}
	if got := Count(filepath.Join(dir, "absent")); got != 0 {
		t.Errorf("Count(absent) = %d, want 0", got)
	}
}

func TestEntriesValidateMarkersHostsAndPublicKeyBlobs(t *testing.T) {
	key := "ssh-ed25519 " + ed25519Blob()
	hash := base64.StdEncoding.EncodeToString(make([]byte, 20))
	for _, tc := range []struct {
		name  string
		entry string
		valid bool
	}{
		{"host list and comment", "one.example.com,two.example.com " + key + " a comment with many words", true},
		{"wildcards and negation", "*.example.com,!other.example.com " + key, true},
		{"IPv6 with port", "[2001:db8::1]:2222 " + key, true},
		{"hashed host", "|1|" + hash + "|" + hash + " " + key, true},
		{"authority", "@cert-authority *.example.com " + key, true},
		{"revoked", "@revoked one.example.com " + key, true},
		{"future format", "one.example.com ssh-future " + publicBlob("ssh-future", []byte{1, 2, 3}), true},
		{"unknown marker", "@unknown one.example.com " + key, false},
		{"duplicate marker", "@revoked @cert-authority one.example.com " + key, false},
		{"negation without host", "! " + key, false},
		{"empty host list component", "one.example.com,,two.example.com " + key, false},
		{"malformed hash", "|1|bad|bad " + key, false},
		{"unknown hash version", "|2|" + hash + "|" + hash + " " + key, false},
		{"invalid base64", "one.example.com ssh-ed25519 !!!!", false},
		{"not a wire key", "one.example.com ssh-ed25519 YWJj", false},
		{"truncated key", "one.example.com ssh-ed25519 " + publicBlob("ssh-ed25519", []byte{0, 0, 0, 32, 1}), false},
		{"wrong key size", "one.example.com ssh-ed25519 " + publicBlob("ssh-ed25519", ssh.Marshal(struct{ Key []byte }{[]byte{1}})), false},
		{"algorithm mismatch", "one.example.com ssh-rsa " + ed25519Blob(), false},
		{"trailing wire data", "one.example.com ssh-ed25519 " + publicBlob("ssh-ed25519", append(ssh.Marshal(struct{ Key []byte }{make([]byte, 32)}), 1)), false},
		{"future empty payload", "one.example.com ssh-future " + publicBlob("ssh-future", nil), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hosts")
			body := "# synthetic public keys\n" + tc.entry + "\n"
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			data, count, err := Read(path)
			if tc.valid {
				if err != nil || count != 1 || string(data) != body {
					t.Fatalf("Read = %q, %d, %v; want unchanged file and one entry", data, count, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "line 2") || data != nil {
				t.Fatalf("Read = %q, %d, %v; want line 2 refusal without data", data, count, err)
			}
			want := 0
			if tc.valid {
				want = 1
			}
			if got := Count(path); got != want {
				t.Fatalf("Count = %d, want %d", got, want)
			}
		})
	}
}

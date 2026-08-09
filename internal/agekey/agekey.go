// Package agekey mints and reads the age identities the keeper decrypts with.
//
// It exists so a faramir host needs no age binary: the identity format is age's
// own, and the library that writes it is the one the keeper reads it with.  It
// does not replace the sops CLI, which is what an operator edits encrypted files
// with.
package agekey

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

// recipientPattern matches the public half.  The identity file holds both, and
// nothing outside the keeper needs the private one.
var recipientPattern = regexp.MustCompile(`age1[0-9a-z]+`)

// Format renders an identity as the file's contents.
func Format(id *age.X25519Identity) string {
	return fmt.Sprintf("# public key: %s\n%s\n", id.Recipient(), id)
}

// Generate mints an identity at path and returns its recipient.
//
// created is false when the file was already there, in which case the existing
// recipient is returned and nothing is written.  Overwriting an age identity
// destroys access to every value it was a recipient for, retroactively, so this
// never clobbers: the file is opened O_EXCL and mode 0400.
func Generate(path string) (recipient string, created bool, err error) {
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if errors.Is(err, os.ErrExist) {
		recipient, err = Recipient(path)
		return recipient, false, err
	}
	if err != nil {
		return "", false, err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		_ = handle.Close()
		_ = os.Remove(path)
		return "", false, err
	}
	if _, err := handle.WriteString(Format(id)); err != nil {
		_ = handle.Close()
		return "", false, err
	}
	// A close error is reported rather than swallowed: the key file would be
	// short, and O_EXCL means the next attempt refuses to overwrite it.
	if err := handle.Close(); err != nil {
		return "", false, err
	}
	return id.Recipient().String(), true, nil
}

// ValidateRecipient reports whether s is something sops will accept where a
// creation rule lists its age recipients.
//
// Checked before it is written rather than when sops next runs, for two
// reasons.  .sops.yaml is world-readable by design, holding public keys and a
// rule and no value, so a private half pasted in place of a public one is the
// key that opens the store handed to every account on the host, the executor's
// included.  And that file is written once and kept, so a recipient sops cannot
// parse is not a run that fails but every later encrypt failing, long after the
// flag that caused it and on a host where nothing still says which flag it was.
//
// The shapes are sops' own, from parseRecipient in its age key source: a bech32
// X25519 or post-quantum hybrid recipient, an age plugin recipient, or an ssh
// public key.  A plugin recipient is taken on its shape alone, the plugin binary
// being the only thing that can parse one and not something a host has to have
// installed to be provisioned.
func ValidateRecipient(s string) error {
	if s == "" {
		return errors.New("empty age recipient")
	}
	// A line break would close the list item this lands in and let what follows
	// be read as YAML of its own, which makes the creation rule only as narrow
	// as the strings put into it.  Refused rather than escaped: no recipient
	// sops accepts carries one.
	if strings.ContainsAny(s, "\n\r") {
		return fmt.Errorf("age recipient contains a line break: %q", s)
	}
	// Named before the shapes below, because both are prefixes no recipient has
	// and both are what somebody reaches for by mistake: the two halves sit in
	// the same file, adjacent, and only one of them is safe to publish.
	if strings.HasPrefix(s, "AGE-SECRET-KEY-") || strings.HasPrefix(s, "AGE-PLUGIN-") {
		return errors.New("that is an age identity, the private half, not a recipient. " +
			".sops.yaml is world-readable, so writing it there hands the key that opens " +
			"the store to every account on this host. Pass the public half instead: the " +
			"age1... line, which is also the '# public key:' comment above the identity")
	}
	switch {
	case strings.HasPrefix(s, "age1pq1"):
		if _, err := age.ParseHybridRecipient(s); err != nil {
			return fmt.Errorf("not a post-quantum age recipient: %w", err)
		}
	// bech32 spells its data part without a '1', so a second one separates a
	// plugin name (age1yubikey1...) rather than being part of the key.  sops
	// tells the two apart this way and so does this.
	case strings.HasPrefix(s, "age1") && strings.Count(s, "1") > 1:
		return nil
	case strings.HasPrefix(s, "age1"):
		if _, err := age.ParseX25519Recipient(s); err != nil {
			return fmt.Errorf("not an age recipient: %w", err)
		}
	case strings.HasPrefix(s, "ssh-"):
		if _, err := agessh.ParseRecipient(s); err != nil {
			return fmt.Errorf("not an ssh public key: %w", err)
		}
	default:
		return fmt.Errorf("unknown recipient type: %q. sops takes an age recipient "+
			"(age1...) or an ssh public key (ssh-ed25519 ..., ssh-rsa ...), not a path "+
			"to one and not an identity file", s)
	}
	return nil
}

// Recipient reads the public half out of an identity file.  The last match, so
// a file carrying both the "# public key:" comment and the identity itself
// yields the identity's own recipient.
func Recipient(path string) (string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = handle.Close() }()
	found := ""
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		if match := recipientPattern.FindString(scanner.Text()); match != "" {
			found = match
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no age recipient in %s", path)
	}
	return found, nil
}

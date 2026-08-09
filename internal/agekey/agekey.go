// Package agekey mints and reads the age identities the keeper decrypts with, so
// a faramir host needs no age binary.  It does not replace the sops CLI, which
// is what edits encrypted files.
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

// recipientPattern matches the public half; nothing outside the keeper needs the
// private one.
var recipientPattern = regexp.MustCompile(`age1[0-9a-z]+`)

// Format renders an identity as the file's contents.
func Format(id *age.X25519Identity) string {
	return fmt.Sprintf("# public key: %s\n%s\n", id.Recipient(), id)
}

// Generate mints an identity at path and returns its recipient.  created is
// false when the file was already there, in which case nothing is written:
// overwriting an identity destroys access to every value it was a recipient for,
// retroactively, so the file is opened O_EXCL and 0400.
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
	// Reported rather than swallowed: the key would be short, and O_EXCL means
	// the next attempt refuses to overwrite it.
	if err := handle.Close(); err != nil {
		return "", false, err
	}
	return id.Recipient().String(), true, nil
}

// ValidateRecipient reports whether s is something sops will accept in a
// creation rule's age recipients.  Checked before it is written: .sops.yaml is
// world-readable, so a private half pasted there hands every account the key
// that opens the store, and the file is written once and kept, so an unparseable
// recipient fails every later encrypt instead of this run.
//
// The shapes are sops' own, from parseRecipient in its age key source.  A plugin
// recipient is taken on its shape alone, the plugin binary being the only thing
// that can parse one.
func ValidateRecipient(s string) error {
	if s == "" {
		return errors.New("empty age recipient")
	}
	// A line break would close the list item and let what follows be read as
	// YAML.  Refused rather than escaped: no recipient sops accepts carries
	// one.
	if strings.ContainsAny(s, "\n\r") {
		return fmt.Errorf("age recipient contains a line break: %q", s)
	}
	// Named before the shapes below: both are prefixes no recipient has, and
	// the two halves sit adjacent in one file with only one safe to publish.
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
	// plugin name (age1yubikey1...).  sops tells the two apart this way.
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

// Recipient reads the public half out of an identity file.
//
// Derived from the private half wherever there is one: the "# public key:"
// comment is a comment, absent from a hand-written key and free to disagree
// with the identity beneath it.  A wrong answer here seals the store to a key
// the host does not hold.  The comment is the fallback, for a file holding a
// recipient and no identity; the last of either wins.
func Recipient(path string) (string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = handle.Close() }()
	derived, found := "", ""
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if id, err := age.ParseX25519Identity(line); err == nil {
			derived = id.Recipient().String()
			continue
		}
		if match := recipientPattern.FindString(line); match != "" {
			found = match
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if derived != "" {
		return derived, nil
	}
	if found == "" {
		return "", fmt.Errorf("no age identity or recipient in %s", path)
	}
	return found, nil
}

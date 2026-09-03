// Package keygen mints the key files an install creates: the age identity the
// keeper decrypts with, and the ed25519 identity the broker lends to brokered
// commands. In process rather than through the age and ssh-keygen binaries, so
// the host needs neither installed and no key appears on a command line. It
// does not replace the sops CLI, which is what edits encrypted files.
package keygen

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"

	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/termsafe"
)

// recipientPattern matches the public half; nothing outside the keeper needs the
// private one.
var recipientPattern = regexp.MustCompile(`age1[0-9a-z]+`)

// Format renders an identity as the file's contents.
func formatAge(id *age.X25519Identity) string {
	return fmt.Sprintf("# public key: %s\n%s\n", id.Recipient(), id)
}

// Age mints an age identity at path and returns its recipient. created is
// false when the file was already there, in which case nothing is written:
// overwriting an identity destroys access to every value it was a recipient
// for, retroactively, so the file is opened O_EXCL and 0400.
func Age(path string) (recipient string, created bool, err error) {
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if errors.Is(err, os.ErrExist) {
		recipient, err = AgeRecipient(path)
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
	if _, err := handle.WriteString(formatAge(id)); err != nil {
		_ = handle.Close()
		return "", false, err
	}
	// Reported rather than swallowed: the key would be short, and O_EXCL means
	// the next attempt refuses to overwrite it.
	if err := settle(handle); err != nil {
		return "", false, err
	}
	return id.Recipient().String(), true, nil
}

// ValidateRecipient reports whether s is something sops will accept in a
// creation rule's age recipients. Checked before it is written: .sops.yaml is
// world-readable, so a private half pasted there hands every account the key
// that opens the secrets, and an unparseable recipient fails every later
// encrypt rather than this run.
//
// The shapes are sops' own, from parseRecipient in its age key source. A
// plugin recipient is taken on its shape alone, the plugin binary being the
// only thing that can parse one.
func ValidateRecipient(s string) error {
	if err := validateRecipient(s); err != nil {
		// Bounded here rather than at each message: what is quoted back is what
		// was pasted, and a pasted key file is a hundred kilobytes of refusal.
		// The parsers below quote it too, so the cut is made on the way out.
		return errors.New(termsafe.Truncate(err.Error(), maxRefusalBytes))
	}
	return nil
}

// maxRefusalBytes is how much of what was given a refusal quotes back: enough
// to recognise the paste, and not the paste.
const maxRefusalBytes = 512

func validateRecipient(s string) error {
	if s == "" {
		return errors.New("empty age recipient")
	}
	// Asked first, and of every line rather than the first: an identity is
	// usually pasted with the file around it, and the line-break refusal below
	// would answer a paste of the private half with a note about YAML.
	if why := privateHalf(s); why != "" {
		return errors.New(why)
	}
	// A line break would close the list item and let what follows be read as
	// YAML. Blocked rather than escaped: no recipient sops accepts carries
	// one.
	if strings.ContainsAny(s, "\n\r") {
		return fmt.Errorf("age recipient contains a line break: %q", s)
	}
	switch {
	case strings.HasPrefix(s, "age1pq1"):
		if _, err := age.ParseHybridRecipient(s); err != nil {
			return fmt.Errorf("not a post-quantum age recipient: %w", err)
		}
	// bech32 spells its data part without a '1', so a second one separates a
	// plugin name (age1yubikey1...). sops tells the two apart this way.
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
		return fmt.Errorf("unknown recipient type: %q. Give an age recipient "+
			"(age1...) or an ssh public key (ssh-ed25519 ..., ssh-rsa ...), not a path "+
			"and not an identity file", s)
	}
	return nil
}

// privateHalf is why this paste is the half that must not be published, or
// empty where it is not one. Both halves sit adjacent in one file and only one
// is safe to write into a world-readable .sops.yaml, so this is the refusal
// worth making by name rather than leaving to "unknown recipient type".
//
// By line, with the line trimmed: an ssh public key carries a free-text
// comment, and a substring search would refuse a valid recipient whose comment
// happened to name one of these.
func privateHalf(s string) string {
	const published = ". .sops.yaml is world-readable, so writing it there hands " +
		"the key that opens the secrets to every account on this host. Pass the " +
		"public half instead"
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "AGE-SECRET-KEY-"), strings.HasPrefix(line, "AGE-PLUGIN-"):
			return "that is an age identity, the private half, not a recipient" +
				published + ": the age1... line, which is also the '# public key:' " +
				"comment above the identity"
		case strings.HasPrefix(line, "-----BEGIN") && strings.Contains(line, "PRIVATE KEY"):
			return "that is a private key, not a recipient" + published +
				": for an ssh key that is the one-line .pub file beside it, " +
				"ssh-ed25519 ... or ssh-rsa ..."
		}
	}
	return ""
}

// AgeRecipient reads the public half out of an identity file.
//
// Derived from the private half wherever there is one: the "# public key:"
// comment is a comment, absent from a hand-written key and free to disagree
// with the identity beneath it. A wrong answer here seals the secrets to a key
// the host does not hold. The comment is the fallback, for a file holding a
// recipient and no identity; the last of either wins.
func AgeRecipient(path string) (string, error) {
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

// settle makes a freshly written key durable: the contents are flushed before
// the file is closed, and the directory entry after it, so a power loss cannot
// leave the name pointing at a file whose data never landed. Every other file
// an install writes it can write again; a private key is the one it cannot.
func settle(handle *os.File) error {
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return err
	}
	if err := handle.Close(); err != nil {
		return err
	}
	return hostfs.SyncDir(filepath.Dir(handle.Name()))
}

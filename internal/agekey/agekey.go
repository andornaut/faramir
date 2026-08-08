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

	"filippo.io/age"
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

// Package knownhosts reads an OpenSSH known_hosts file: which host keys are in
// it, and how many.
//
// Only the parsing. Pinning a key is the install's and reporting on what is
// pinned is a diagnosis's, and both ask this the same question so that a host
// key counted by one is counted by the other.
package knownhosts

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// GlobalFile is the file ssh consults before any account's own, so one
// copy answers for the executor, the operator and root at once. Root-owned and
// outside every home, which makes it the arrangement to prefer.
const GlobalFile = "/etc/ssh/ssh_known_hosts"

// keyTypes are the algorithm prefixes a host key line can carry.
// Prefixes rather than an exact list: future formats retain envelope validation
// even when their algorithm-specific payload is not understood here.
var keyTypes = []string{"ssh-", "ecdsa-", "sk-", "webauthn-"}

// Read reads a known_hosts file and reports how many host keys it
// holds, refusing a file that is not one: what the flag names is copied into an
// account that must never hold key material.
func Read(path string) ([]byte, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		return nil, 0, fmt.Errorf("%s holds a private key\n"+
			"  pass a known_hosts file, such as ~/.ssh/known_hosts", path)
	}
	entries, bad := parse(data)
	if bad != 0 {
		return nil, 0, fmt.Errorf("%s line %d is not a known_hosts entry", path, bad)
	}
	return data, entries, nil
}

// parse counts the host key entries in a known_hosts file and reports
// the first line that is not one, zero when every line parses. Blank lines and
// comments are neither.
func parse(data []byte) (entries, bad int) {
	for i, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		// @cert-authority and @revoked qualify the name that follows them.
		if strings.HasPrefix(fields[0], "@") {
			if fields[0] != "@cert-authority" && fields[0] != "@revoked" {
				if bad == 0 {
					bad = i + 1
				}
				continue
			}
			fields = fields[1:]
		}
		// A hashed entry is still name, type and key; only the name is opaque.
		if len(fields) < 3 || !validHosts(fields[0]) || !validKey(fields[1], fields[2]) {
			if bad == 0 {
				bad = i + 1
			}
			continue
		}
		entries++
	}
	return entries, bad
}

// Host patterns permit wildcards, negation, address lists and bracketed ports.
// Hashed names use OpenSSH's version 1 HMAC-SHA1 format (20-byte salt and hash).
func validHosts(hosts string) bool {
	if strings.HasPrefix(hosts, "|") {
		parts := strings.Split(hosts, "|")
		if len(parts) != 4 || parts[1] != "1" {
			return false
		}
		for _, part := range parts[2:] {
			decoded, err := base64.StdEncoding.DecodeString(part)
			if err != nil || len(decoded) != 20 {
				return false
			}
		}
		return true
	}
	for pattern := range strings.SplitSeq(hosts, ",") {
		pattern = strings.TrimPrefix(pattern, "!")
		if pattern == "" {
			return false
		}
	}
	return true
}

func validKey(algorithm, encoded string) bool {
	if !hasPrefixIn(algorithm, keyTypes) {
		return false
	}
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	var envelope struct {
		Algorithm string
		Body      []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(blob, &envelope); err != nil || envelope.Algorithm != algorithm || len(envelope.Body) == 0 {
		return false
	}
	_, err = ssh.ParsePublicKey(blob)
	// Unknown formats remain forward compatible. Their envelope is checked,
	// but only the OpenSSH version using the file can validate their payload.
	// The parser has no typed error for an unknown algorithm.
	return err == nil || err.Error() == fmt.Sprintf("ssh: unknown key algorithm: %q", algorithm)
}

func hasPrefixIn(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// Count reports how many validated host key entries a file contains, and
// zero for one that is absent. Future key formats receive envelope validation
// only; their usability depends on the installed OpenSSH. Lenient where Read
// refuses: ssh ignores a line it cannot parse, so the entries either side of a
// bad one still verify their hosts.
func Count(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	entries, _ := parse(data)
	return entries
}

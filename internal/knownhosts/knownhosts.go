// Package knownhosts reads an OpenSSH known_hosts file: which host keys are in
// it, and how many.
//
// Only the parsing. Pinning a key is the install's and reporting on what is
// pinned is a diagnosis's, and both ask this the same question so that a host
// key counted by one is counted by the other.
package knownhosts

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// GlobalFile is the file ssh consults before any account's own, so one
// copy answers for the executor, the operator and root at once. Root-owned and
// outside every home, which makes it the arrangement to prefer.
const GlobalFile = "/etc/ssh/ssh_known_hosts"

// keyTypes are the algorithm prefixes a host key line can carry.
// Prefixes rather than an exact list: a type a later OpenSSH adds is still a
// host key.
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
		return nil, 0, fmt.Errorf("%s holds a private key. This takes the public "+
			"host keys ssh verifies a host against, which is ~/.ssh/known_hosts", path)
	}
	entries, bad := parse(data)
	if bad != 0 {
		return nil, 0, fmt.Errorf("%s line %d is not a known_hosts entry, which is "+
			"a host name, a key type and a key. Check the path names the right file", path, bad)
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
			fields = fields[1:]
		}
		// A hashed entry is still name, type and key; only the name is opaque.
		if len(fields) < 3 || !hasPrefixIn(fields[1], keyTypes) {
			if bad == 0 {
				bad = i + 1
			}
			continue
		}
		entries++
	}
	return entries, bad
}

func hasPrefixIn(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// Count reports how many host keys ssh would take from a file, and
// zero for one that is absent. Lenient where Read refuses: ssh
// ignores a line it cannot parse, so the entries either side of a bad one still
// verify their hosts.
func Count(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	entries, _ := parse(data)
	return entries
}

// Package secretlink reads one secret out of a file the operator's own tools
// maintain, rather than out of the managed sops store. The file stays where
// its tool expects it, so rotating a credential is that tool's business.
//
// A link is for redaction as much as injection: a value the agent can already
// read is plaintext one command away, and linking it puts it in the value set
// so a brokered command that prints it gets a token back, with the deny rules
// taking away the direct read.
//
// No error here carries file content. A decoder's own message often quotes the
// line it failed on, and these messages reach the daemon log and `--check`, so
// the parse errors are replaced rather than wrapped.
package secretlink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	yaml "go.yaml.in/yaml/v3"

	"github.com/andornaut/faramir/internal/termsafe"
)

// The kinds, which are how a file is read rather than what it is called.
const (
	// KindText is the whole file, surrounding whitespace trimmed: a keyfile or a
	// single-line token.
	KindText = "text"
	// kindBase64 is the whole file encoded, for one that is not text. The value
	// injected is the encoding, so whatever consumes it decodes.
	kindBase64 = "base64"
	// kindJSON, KindYAML, kindTOML and kindINI select one value out of a
	// structured file.
	kindJSON = "json"
	KindYAML = "yaml"
	kindTOML = "toml"
	kindINI  = "ini"
)

// maxBytes bounds a linked file: a credential file is small, and a link pointed
// at something else should fail rather than be read into the value set.
const maxBytes = 1 << 20

// Kinds is every kind, for the config parser's error message. Ordered as
// declared: the whole-file kinds first, then the ones that select.
func Kinds() []string {
	return []string{KindText, kindBase64, kindJSON, KindYAML, kindTOML, kindINI}
}

// NeedsKey reports whether a kind selects part of a file, and so requires a
// `key`. The whole-file kinds refuse one, a key there naming nothing.
func NeedsKey(kind string) bool {
	switch kind {
	case kindJSON, KindYAML, kindTOML, kindINI:
		return true
	}
	return false
}

// Read returns the value a link selects. The error says what is wrong with the
// file or the selector and never what is in it.
func Read(path, kind, key string) (string, error) {
	data, err := readBounded(path)
	if err != nil {
		return "", err
	}
	return extract(kind, key, data)
}

// readBounded reads at most maxBytes plus one byte, so a file over the cap is
// reported rather than truncated into the value set.
//
// O_NONBLOCK and a regular-file check, because this runs in the broker's load
// path and a path that blocks on open blocks the daemon with it: opening a FIFO
// for reading waits for a writer that never comes, and the unit never finishes
// starting. Refused as soon as it is known rather than waited on: a link names
// a credential file, and a FIFO or a device is not one. O_NONBLOCK is a no-op
// on a regular file, so this costs the ordinary case nothing.
func readBounded(path string) ([]byte, error) {
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	info, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("is a %s, not a regular file", kindOf(info.Mode()))
	}
	data, err := io.ReadAll(io.LimitReader(fh, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("is larger than %d bytes, which is too large for a "+
			"credential file", maxBytes)
	}
	return data, nil
}

// kindOf names what a path turned out to be, for a refusal that says which.
func kindOf(mode os.FileMode) string {
	switch {
	case mode&os.ModeNamedPipe != 0:
		return "named pipe"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		return "character device"
	case mode&os.ModeDevice != 0:
		return "block device"
	case mode.IsDir():
		return "directory"
	}
	return "special file"
}

// extract pulls the value out of a file's bytes.
func extract(kind, key string, data []byte) (string, error) {
	switch kind {
	case KindText:
		if !utf8.Valid(data) {
			return "", errors.New("is not valid UTF-8, so it cannot be redacted from " +
				"output or held in an environment variable; use type = \"base64\"")
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			return "", errors.New("holds no value")
		}
		return value, nil
	case kindBase64:
		if len(data) == 0 {
			return "", errors.New("holds no value")
		}
		return base64.StdEncoding.EncodeToString(data), nil
	case kindJSON:
		var tree any
		if err := json.Unmarshal(data, &tree); err != nil {
			return "", errors.New("is not valid JSON")
		}
		return selectPath(tree, key)
	case KindYAML:
		var tree any
		if err := yaml.Unmarshal(data, &tree); err != nil {
			return "", errors.New("is not valid YAML")
		}
		return selectPath(tree, key)
	case kindTOML:
		var table map[string]any
		if err := toml.Unmarshal(data, &table); err != nil {
			return "", errors.New("is not valid TOML")
		}
		return selectPath(table, key)
	case kindINI:
		return selectINI(data, key)
	}
	return "", fmt.Errorf("unknown type %q; known types: %s",
		kind, strings.Join(Kinds(), ", "))
}

// Refusal is what a caller may show when Read failed: the error itself, and
// where the kind selects, the selectors the file does offer. Names only and
// never a value, which is what makes it safe to print and to relay across a
// process boundary.
//
// The offers are read again rather than threaded out of the failure: the error
// deliberately carries nothing of the file, and this is the one place allowed
// to say what is in it. Through the same bounded read, or a link pointed at
// something enormous would be refused for its size and then slurped anyway to
// enumerate it.
func Refusal(path, kind string, cause error) error {
	keys, err := keysIn(path, kind)
	if err != nil || len(keys) == 0 {
		return cause
	}
	// Rendered, not printed: these are names out of a file another tool writes,
	// and this message goes to a terminal. A key carrying a carriage return or
	// an escape sequence would make the row read as something other than what
	// the file holds, which is the same reason an entry carrying one is refused
	// where it is written.
	shown := make([]string, len(keys))
	for i, key := range keys {
		// Truncate rather than Bound, which points the reader at an audit
		// record: this is a refusal printed to a terminal, and no record holds
		// the keys a file offers.
		shown[i] = termsafe.Truncate(termsafe.Arg(key), maxKeyChars)
	}
	return fmt.Errorf("%w\nthis file offers: %s", cause, strings.Join(shown, ", "))
}

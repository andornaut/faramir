package keeper

// Which files the store names, and what state each is in on disk.

import (
	goerrors "errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/fserr"
)

// FileState is one managed file's identity on disk: enough to notice an edit,
// nothing about its contents. Nanoseconds, a serialisation that rounds turning
// an edit made within the same second into no change.
type FileState struct {
	Path  string `json:"path"`
	MTime int64  `json:"mtime_unix_nano"`
	Size  int64  `json:"size"`
}

// Resolve expands each managed store entry against the filesystem. Every entry
// is a glob, a literal path being one with no metacharacters, and matches are
// deduplicated.
//
// Per request rather than at config load, so a file added beside the others is
// picked up on the next refresh. It is also the only place that can resolve:
// the secrets directory is group-readable by this uid alone.
//
// The two kinds of not-there are returned separately: an entry that named
// nothing is a secrets directory not written yet, and a file that is there and
// will not open is a value the redactor is missing without knowing it. Only
// the second is an error.
func Resolve(files []string) (paths, errors, unresolved []string) {
	paths = []string{}
	errors = []string{}
	unresolved = []string{}
	seen := map[string]bool{}
	for _, entry := range files {
		matches, err := filepath.Glob(entry)
		if err != nil {
			// Only ErrBadPattern, which config rejects at load.
			errors = append(errors, entry+": "+err.Error())
			continue
		}
		if len(matches) == 0 {
			unresolved = append(unresolved, entry+": "+unresolvedReason(entry))
			continue
		}
		for _, match := range matches {
			if seen[match] {
				continue
			}
			seen[match] = true
			paths = append(paths, match)
		}
	}
	// The entries are alternatives rather than an inventory, so "did anything
	// match" belongs to the set. It is asked at all because a store that matched
	// nothing is a broker redacting nothing, which has to be told apart from one
	// whose files have not been written yet.
	if len(paths) > 0 {
		unresolved = []string{}
	}
	return paths, errors, unresolved
}

// NoMatchReason is the reason an entry gives when nothing is wrong with the
// directory and it simply holds no matching file. Exported because a caller
// rendering it adds a guess at why -- not written yet, filesystem not mounted
// -- which belongs only to this one: the others name what stopped them.
const NoMatchReason = "matched no files"

// refusedPrefix opens the reason an entry gives when the directory it names
// could not be read at all.
const refusedPrefix = "cannot read "

// UnresolvedWasRefused reports whether an entry Resolve returned says the
// search was stopped rather than that it found nothing. A caller grades the
// two differently: an empty directory is what every host looks like before its
// first secret is written, and one this account may not read is what no
// working install looks like.
//
// Matched on the reason, which Resolve writes after the entry and ": ". A
// pattern carrying that text itself would read as one of these; the patterns
// are derived from the config directory rather than typed, so there is none to
// carry it.
func UnresolvedWasRefused(entry string) bool {
	_, reason, found := strings.Cut(entry, ": ")
	return found && strings.HasPrefix(reason, refusedPrefix)
}

// unresolvedReason says why an entry named nothing, separating "not written
// yet" from "this process cannot look". The two are corrected differently --
// write a file, or give the account the directory back -- and Glob reports
// neither: it returns no matches and no error either way.
func unresolvedReason(entry string) string {
	if isPattern(entry) {
		// The directory the pattern names, read the way Glob reads it. Skipped
		// where that part is itself a pattern, there being no one directory to
		// name.
		dir := filepath.Dir(entry)
		if isPattern(dir) {
			return NoMatchReason
		}
		if err := readable(dir); err != nil {
			return refusedPrefix + fserr.At(dir, err).Error()
		}
		return NoMatchReason
	}
	if _, err := os.Stat(entry); err != nil {
		return err.Error()
	}
	// Glob uses Lstat and os.Stat follows, so this is a dangling symlink.
	return "no such file"
}

// readable is whether this process could have listed a directory, asked with
// one entry rather than with ReadDir: the answer is the open, and a store that
// matched no *.sops.yml can still hold a great many other files.
func readable(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Close() }()
	if _, err := handle.Readdirnames(1); err != nil && !goerrors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// isPattern reports whether an entry has glob metacharacters. The set filepath
// treats as meta on this platform; a backslash escapes on Unix, so it counts.
func isPattern(entry string) bool { return strings.ContainsAny(entry, `*?[\`) }

// StatAll fingerprints every managed file: no key, no sops, no contents, the
// broker calling this on every poll. A file that cannot be stat-ed is an error
// rather than a missing entry.
func StatAll(secrets config.SecretConfig) ([]FileState, []string, []string) {
	state := []FileState{}
	paths, errors, unresolved := Resolve(secrets.Patterns)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			errors = append(errors, path+": "+err.Error())
			continue
		}
		state = append(state, FileState{
			Path: path, MTime: info.ModTime().UnixNano(), Size: info.Size()})
	}
	return state, errors, unresolved
}

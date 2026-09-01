package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	yaml "go.yaml.in/yaml/v3"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sopsrule"
	"github.com/andornaut/faramir/internal/termsafe"
)

// errNoManagedFiles is what `edit` reports when the secrets directory is empty.
// `reseal` has its own, saying what it in particular had nothing to do.
var errNoManagedFiles = errors.New("no managed sops files: the managed store named " +
	"none, so there is nothing to open. Write the first one with `faramir vault " +
	"add NAME`")

// managedSuffix is what a managed file ends in. One spelling: the suffix
// decides the store format sops writes and is what the [secret] pattern
// matches, so it stays on the file and off the argument.
const managedSuffix = ".sops.yml"

// managedSuffixes is what a name already spelled in full ends in. A write always
// produces managedSuffix, but a [secret] pattern may name any of these, so a name
// carrying one is the operator naming the file rather than the stem of one.
var managedSuffixes = []string{managedSuffix, ".sops.yaml", ".sops.json"}

// carriesManagedSuffix reports whether this is already a managed file's name.
// Asked separately from the [secret] patterns: a name may end in a managed
// suffix and still match no pattern, and appending a second suffix to that one
// refuses it under a name the operator never typed.
func carriesManagedSuffix(path string) bool {
	for _, suffix := range managedSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// managedStem is a managed file's name without its suffix, which is what an
// operator types.
func managedStem(path string) string {
	stem, _ := strings.CutSuffix(filepath.Base(path), managedSuffix)
	return stem
}

// Resolve maps the argument onto one of the configured files, matching a
// bare name against each base name and against each name without its suffix.
// Anything unmanaged is refused, an edit outside the list being a file the
// broker never reads.
func Resolve(managed []string, arg string) (string, error) {
	if len(managed) == 0 {
		return "", errNoManagedFiles
	}
	var matches []string
	wanted := filepath.Clean(arg)
	for _, file := range managed {
		if filepath.Clean(file) == wanted || filepath.Base(file) == arg ||
			managedStem(file) == arg {
			matches = append(matches, file)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("%s is not a managed file; the managed store names %s",
			arg, strings.Join(managed, ", "))
	default:
		return "", fmt.Errorf("%s matches more than one managed file (%s); name the full path",
			arg, strings.Join(matches, ", "))
	}
}

// NewManagedPath is where a new file goes, or why it may not go there.
// Relative to the secrets directory, which is the only place the broker reads,
// and checked against the patterns rather than the directory alone: a name the
// globs do not match encrypts perfectly well and is then served to nobody.
func NewManagedPath(cfg *config.Config, name string) (string, error) {
	if len(cfg.Secret.Patterns) == 0 {
		return "", errors.New("[secret] patterns names no location for a managed file")
	}
	dir := filepath.Dir(cfg.Secret.Patterns[0])
	// Asked before a path is built out of it: Join drops an empty name and a
	// ".", so both would be answered about the secrets directory with a suffix
	// glued on, which is a path the operator never typed and cannot correct.
	if strings.TrimSpace(name) == "" || filepath.Clean(name) == "." {
		return "", fmt.Errorf("name the file to create: a name relative to %s, "+
			"which is where a managed file lives", dir)
	}
	if err := refuseUnprintable(name); err != nil {
		return "", err
	}
	target := name
	if !filepath.IsAbs(target) {
		target = filepath.Join(dir, target)
	}
	target = filepath.Clean(target)

	// The suffix is faramir's, not the operator's: they pick a name and this
	// writes a YAML store. A name that already carries a managed suffix is taken
	// as it stands, so naming a file in full is neither wrong nor doubled: the
	// refusal below then names what was typed, which is what the operator has to
	// correct.
	if !matchesPatterns(cfg.Secret.Patterns, target) && !carriesManagedSuffix(target) {
		target += managedSuffix
	}
	if !matchesPatterns(cfg.Secret.Patterns, target) {
		// The patterns in full, not their file names: a pattern shown as
		// "*.sops.yml" is one /tmp/outside.sops.yml plainly matches, and what it
		// misses is the directory the glob names.
		return "", fmt.Errorf("%s matches none of the [secret] patterns (%s), so the "+
			"broker would never read it and nothing in it could be named as a ref",
			target, joinPatterns(cfg.Secret.Patterns))
	}
	if exists(target) {
		return "", fmt.Errorf("%s is already there; `faramir vault edit %s` opens it",
			target, filepath.Base(target))
	}
	// Named rather than left to the write to fail on: a missing directory here
	// means an install that has not been run.
	if !exists(dir) {
		return "", fmt.Errorf("%s is not there, so there is nowhere to put a managed "+
			"file: `sudo faramir init` creates it", dir)
	}
	return target, nil
}

// refuseUnprintable holds a managed file's name to bytes that can be shown and
// typed. The same check a [[secret.block]] entry gets, for a different reason:
// a name is not a rule, so a newline splits nothing, but it is printed back by
// every command that touches the file and typed into every shell command that
// reaches it. Refused where it is written rather than escaped where it is
// shown, which would leave an operator with a file they cannot name.
//
// Decoded byte by byte rather than ranged over: ranging yields U+FFFD for a
// byte that is not valid UTF-8, which is not Actionable, so the check would
// not see it.
func refuseUnprintable(name string) error {
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		if r == utf8.RuneError && size == 1 {
			return fmt.Errorf("name %q carries a byte at offset %d that is not "+
				"valid UTF-8, so nothing can print the file's name back to you",
				config.Shown(name), i)
		}
		if termsafe.Actionable(r) {
			return fmt.Errorf("name %q carries %q at offset %d, which a terminal "+
				"acts on rather than draws", config.Shown(name), r, i)
		}
		i += size
	}
	return nil
}

// matchesPatterns reports whether the broker would read this path.
func matchesPatterns(patterns []string, target string) bool {
	for _, pattern := range patterns {
		if ok, _ := filepath.Match(pattern, target); ok {
			return true
		}
	}
	return false
}

// joinPatterns names the configured entries as a message quotes them: in full,
// each one being what a path is actually matched against.
func joinPatterns(patterns []string) string {
	out := append([]string{}, patterns...)
	slices.Sort(out)
	return strings.Join(out, ", ")
}

// ManagedFile is one file as `ls` reports it.
type ManagedFile struct {
	// Name is what an operator types, and Path is what is on disk. Both, so the
	// listing can be pasted into another command and read as a path.
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Refs       []string `json:"refs"`
	Recipients []string `json:"recipients"`
	// Drifted is true where the file is sealed to a set the rule no longer names,
	// which is what `faramir reader reseal` is for.
	Drifted bool `json:"drifted"`
	// Problem is why this file could not be read or parsed, and "" otherwise. A
	// file the broker would refuse is what an operator comes here to find, so it
	// is a row rather than a reason to stop.
	Problem string `json:"problem,omitempty"`
}

// StateOf is the one word a listing has room for.
func StateOf(file ManagedFile) string {
	switch {
	case file.Problem != "":
		return file.Problem
	case file.Drifted:
		return "drifted"
	}
	return "ok"
}

// DescribeManaged reads one file without decrypting it: both the ref names and
// the recipients are cleartext in a sops file.
func DescribeManaged(path string, wanted []string, haveRule bool) ManagedFile {
	file := ManagedFile{Name: managedStem(path), Path: path}
	recipients, err := sopsrule.SealedTo(path)
	if err != nil {
		file.Problem = "not sealed to any age recipient"
		return file
	}
	file.Recipients = recipients
	file.Drifted = haveRule && !sopsrule.Same(recipients, wanted)

	refs, err := RefsIn(path)
	if err != nil {
		file.Problem = err.Error()
		return file
	}
	file.Refs = refs
	return file
}

// RefsIn is the refs a managed file names, taken from its structure rather than
// its values. sops encrypts values and leaves keys readable, so this answers
// without the age key: [keeper.Flatten] is given the file as it sits on disk,
// so each ref maps onto ciphertext and only the names are kept.
func RefsIn(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("does not parse: %w", err)
	}
	refs := make([]string, 0, len(doc))
	for ref := range keeper.Flatten(doc) {
		refs = append(refs, ref)
	}
	slices.Sort(refs)
	return refs, nil
}

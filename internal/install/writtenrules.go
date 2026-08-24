package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
)

// What faramir last wrote into each agent's configuration, so a rule no entry
// backs any more can be taken out again.
//
// The merge cannot work this out for itself. An agent's config is the
// operator's file, faramir writes into a list that already holds their own
// entries, and a rendered rule carries no sign of who put it there: an entry
// removed from the config leaves its rules behind, and the next render adds the
// new ones beside them. That is a rule refusing something nothing declares, and
// nothing removes it.
//
// Nor can the shape of a rule answer it. `secrets*` renders to
// `Read(**/secrets*)`, and this install's own store renders to
// `Read(<configdir>/secrets/**)`: both carry the word, one is stale and one
// must never be touched. Only a record of what was written distinguishes them.
//
// Advisory, and allowed to be stale, like the enrolment record beside it. A
// missing or unreadable file means this run knows of nothing it wrote, so it
// removes nothing and adds what it renders: the same behaviour as before there
// was a record at all. Nothing here is a boundary.
const writtenRulesFile = "written-rules.json"

// writtenRulesPath is where the record lives, beside the config it belongs to.
func writtenRulesPath(configDir string) string {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	return filepath.Join(configDir, writtenRulesFile)
}

// readWrittenRules is what faramir last wrote, keyed by the absolute path of
// the file it wrote it into. A file that will not parse reads as empty.
func readWrittenRules(configDir string) map[string][]string {
	body, err := os.ReadFile(writtenRulesPath(configDir))
	if err != nil {
		return nil
	}
	var written map[string][]string
	if err := json.Unmarshal(body, &written); err != nil {
		return nil
	}
	return written
}

// recordWrittenRules replaces this file's entry with what was just rendered
// into it. Sorted so the record does not churn between runs, and an entry that
// renders nothing is dropped rather than kept empty.
func recordWrittenRules(configDir, path string, rules []string) error {
	// What is on disk now, so the write below refuses a record another run
	// replaced in between. This is a read-modify-write like the config and the
	// enrolment record, and it loses the same way: two runs each read the file,
	// each add their own entry, and the second write drops the first. What goes
	// with it is doctor's ability to tell faramir's rules from the operator's in
	// that file, so it stops offering to clean them up.
	before, err := writtenRulesDigest(configDir)
	if err != nil {
		return err
	}
	written := readWrittenRules(configDir)
	if written == nil {
		written = map[string][]string{}
	}
	if len(rules) == 0 {
		delete(written, path)
	} else {
		sorted := slices.Clone(rules)
		sort.Strings(sorted)
		written[path] = slices.Compact(sorted)
	}
	if len(written) == 0 {
		// Nothing left to say. Removing it keeps a host that has been uninstalled
		// from carrying a record of files it no longer writes.
		//
		// Held to the same digest as the write below: this run's map is empty
		// because its own read found one entry and it dropped it, and another
		// run that added an entry in between would have the whole record removed
		// under it. Refused rather than removed, which is what the write does.
		if err := unchangedSince(configDir, before); err != nil {
			return err
		}
		if err := os.Remove(writtenRulesPath(configDir)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	body, marshalErr := json.MarshalIndent(written, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	// Written beside the file and renamed over it, as the enrolment record is:
	// a run interrupted partway through a truncating write leaves a record that
	// does not parse, which readWrittenRules takes for having written nothing.
	_, err = fsys{}.writeFileExpecting(
		writtenRulesPath(configDir), append(body, '\n'), 0o600, keep, keep, before)
	return err
}

// unchangedSince refuses a removal whose caller read a record that has since
// been replaced. writeFileExpecting makes the same check for a write, under the
// temporary name it holds; a removal has no such name to hold, so the window
// between this and the unlink is open. It is narrower than the one it closes,
// which spans the caller's whole read-modify-write.
func unchangedSince(configDir string, expect []byte) error {
	if expect == nil {
		return nil
	}
	now, err := writtenRulesDigest(configDir)
	if err != nil {
		return err
	}
	if bytes.Equal(now, expect) {
		return nil
	}
	return fmt.Errorf("%s changed while this was working on it, so nothing was "+
		"removed: another faramir command edited it. Run them one at a time, then "+
		"run this again", writtenRulesPath(configDir))
}

// writtenRulesDigest is the record as it stands, or nil where there is none: a
// first run writes the file rather than editing it. A file that will not parse
// still has a digest, so a run that replaces one is refused the same way as a
// run that replaces a good one.
func writtenRulesDigest(configDir string) ([]byte, error) {
	body, err := os.ReadFile(writtenRulesPath(configDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return sum[:], nil
}

// jsonStrings is every string in a list anywhere in a JSON document, which is
// the shape every rule faramir renders takes: a deny list, a permission list,
// a pattern list. Sorted and deduplicated.
//
// The values rather than where they sit: a rule moved from one list to another
// between releases is the same rule, and a record keyed on position would leave
// the old one behind on the run that moved it.
func jsonStrings(document []byte) []string {
	var parsed any
	if err := json.Unmarshal(document, &parsed); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for _, nested := range typed {
				walk(nested)
			}
		case []any:
			for _, element := range typed {
				if text, isString := element.(string); isString {
					out = append(out, text)
					continue
				}
				walk(element)
			}
		}
	}
	walk(parsed)
	sort.Strings(out)
	return slices.Compact(out)
}

package secretstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeperclient"
	"github.com/andornaut/faramir/internal/secretlink"
)

// loadLinks reads every [[secrets.link]] file.  Per-link failures are collected
// rather than aborting, so one broken link does not blank the value set.
//
// The two ways a link can fail to produce a value are kept apart, and they mean
// opposite things, the same way they do for a managed sops file:
//
//   - A path that is not there is an entry naming nothing.  The credential has
//     been removed from the machine (a logout, a tool uninstalled), so there is
//     nothing left to leak and nothing to redact.  Reported, not fatal.
//   - A file that is there and will not read or parse is an error.  The value is
//     still on disk and can still reach output, and the redactor does not have
//     it, so the broker refuses to serve while it is set.
//
// The permission case is the second kind on purpose: a link whose ACL was
// dropped by a tool rewriting its own file is exactly a value the redactor is
// missing without knowing it.
func loadLinks(links []config.Link) (values map[string]string,
	state []keeperclient.FileState, loadErrors, unresolved []string) {
	values = map[string]string{}
	state = []keeperclient.FileState{}
	loadErrors = []string{}
	unresolved = []string{}
	for _, link := range links {
		info, err := os.Stat(link.Path)
		if err != nil {
			if os.IsNotExist(err) {
				unresolved = append(unresolved,
					fmt.Sprintf("%s: %s: no such file", link.Ref, link.Path))
				continue
			}
			loadErrors = append(loadErrors, linkError(link, err))
			continue
		}
		// Fingerprinted whether or not it reads.  statLinks records every file
		// that is there, so a link left out here because it would not parse would
		// differ from the poll's view on every request and reload the whole set
		// each time, logging a change that never happened.
		state = append(state, keeperclient.FileState{
			Path: link.Path, MTime: info.ModTime().UnixNano(), Size: info.Size()})

		value, err := secretlink.Read(link.Path, link.Type, link.Key)
		if err != nil {
			loadErrors = append(loadErrors, linkError(link, err))
			continue
		}
		values[link.Ref] = value
	}
	return values, state, loadErrors, unresolved
}

// statLinks fingerprints the linked files without reading them, which is what
// the refresh poll needs.  A link whose file has gone contributes no entry, so
// the set differs and a reload follows.
func statLinks(links []config.Link) []keeperclient.FileState {
	state := make([]keeperclient.FileState, 0, len(links))
	for _, link := range links {
		info, err := os.Stat(link.Path)
		if err != nil {
			continue
		}
		state = append(state, keeperclient.FileState{
			Path: link.Path, MTime: info.ModTime().UnixNano(), Size: info.Size()})
	}
	return state
}

// linkError puts the ref in front of a reason, naming the file unless the error
// already does.  No error from internal/secretlink carries file content, which
// is what makes it safe to log and to report from `--check`.
func linkError(link config.Link, err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return fmt.Sprintf("%s: %v", link.Ref, err)
	}
	return fmt.Sprintf("%s: %s %v", link.Ref, link.Path, err)
}

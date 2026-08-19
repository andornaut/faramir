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

// loadLinks reads every [[secret.link]] file. Per-link failures are collected
// rather than aborting, so one broken link does not blank the value set. The
// two ways a link can fail mean opposite things, as they do for a managed sops
// file:
//
//   - A path that is not there is an entry naming nothing: the credential has
//     left the machine, so there is nothing to leak and nothing to redact.
//     Reported, not fatal.
//   - A file that is there and will not read or parse is an error: the value is
//     still on disk and the redactor does not have it, so the broker refuses to
//     serve while it is set. The permission case is this kind.
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
		// Fingerprinted whether or not it reads: statLinks records every file that
		// is there, so one left out here would differ from the poll's view on every
		// request and reload the whole set each time.
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
// the refresh poll needs. A link whose file has gone contributes no entry, so
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
// already does. No error from internal/secretlink carries file content, which
// is what makes it safe to log.
func linkError(link config.Link, err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return fmt.Sprintf("%s: %v", link.Ref, err)
	}
	return fmt.Sprintf("%s: %s %v", link.Ref, link.Path, err)
}

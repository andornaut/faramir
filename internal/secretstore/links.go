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
// rather than aborting, so one broken link does not blank the value set.
//
// A link that fails degrades one ref and no others. That is the whole of what
// separates it from a managed sops file, which holds any number of refs and
// names none of them until it decrypts: a file that did not load leaves the
// broker knowing values are missing and not which, so it stops serving, while a
// link that did not load is a ref it can name and refuse on its own.
//
// Two reasons come back for each failure. The short one is handed to whoever
// asked for the ref, so it carries no path: a linked file is one of the
// operator's own, refused to the agent's file tools, and naming it would give
// away the location of a credential. The long one carries the path and goes to
// the daemon log and the operator's report.
func loadLinks(links []config.Link) (values map[string]string,
	state []keeperclient.FileState, degraded map[string]string, detail []string) {
	values = map[string]string{}
	state = []keeperclient.FileState{}
	degraded = map[string]string{}
	detail = []string{}
	for _, link := range links {
		info, err := os.Stat(link.Path)
		if err != nil {
			degraded[link.Ref] = reason(err)
			detail = append(detail, linkError(link, err))
			continue
		}
		// Fingerprinted whether or not it reads: statLinks records every file that
		// is there, so one left out here would differ from the poll's view on every
		// request and reload the whole set each time.
		state = append(state, keeperclient.FileState{
			Path: link.Path, MTime: info.ModTime().UnixNano(), Size: info.Size()})

		value, err := secretlink.Read(link.Path, link.Type, link.Key)
		if err != nil {
			degraded[link.Ref] = reason(err)
			detail = append(detail, linkError(link, err))
			continue
		}
		values[link.Ref] = value
	}
	return values, state, degraded, detail
}

// reason is what a caller asking for the ref is told: the kind of failure, in
// terms of the entry rather than of the file, and never the path.
//
// The three are not the same fault. A file that is not there is a credential
// that has left the machine or a home not yet mounted, and there is no
// plaintext left to cover. A file that will not open is one whose plaintext is
// still on disk, so the value it holds can still reach output with nothing
// holding it. One that opens and yields nothing is a selector that no longer
// matches what the owning tool writes.
func reason(err error) string {
	switch {
	case os.IsNotExist(err):
		return "the file it names is not there"
	case os.IsPermission(err):
		return "the broker cannot read the file it names"
	}
	return "the file it names yielded no value"
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
	if _, ok := errors.AsType[*fs.PathError](err); ok {
		return fmt.Sprintf("%s: %v", link.Ref, err)
	}
	return fmt.Sprintf("%s: %s %v", link.Ref, link.Path, err)
}

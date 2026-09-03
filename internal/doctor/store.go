package doctor

import (
	"fmt"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/brokercheck"
	"github.com/andornaut/faramir/internal/keeper"
)

// storeFinding is what the `managed store` check reports: what the store holds,
// and whether anything about it is wrong.
//
// An empty value set is a warning rather than a failure, in every shape it
// comes in. A host that manages no credentials is a host with nothing to leak,
// and a host that has not written its first secret is every install on its
// first day. What still fails is a managed file that was found and did not
// load: there the broker knows values exist that it cannot cover, and it
// refuses the ops rather than running them.
//
// The warning matters because a store on a filesystem that is not mounted is
// the one case that looks like an empty install and is not. Nothing can tell
// those apart, so both are reported and neither stops the host.
func storeFinding(c brokercheck.CheckReport) (Status, string) {
	switch {
	case len(c.Secrets.Errors) > 0:
		// First, and on its own: the daemon refuses every redacted op while one
		// file did not load, whatever else did, so a ref count beside it would
		// describe a store that is not being served.
		return StatusFailed, brokercheck.LoadErrorDetail(c.Secrets.Errors)
	case len(c.Secrets.Patterns) == 0 && c.Secrets.Links == 0:
		return StatusWarn, "no managed sops files and no [[secret.link]] entries are configured, so commands " +
			"run with nothing injected and nothing redacted"
	case len(c.Secrets.UnresolvedPatterns) > 0:
		// A warning rather than a failure, because this cannot tell a host that
		// keeps no store from one whose store went missing: the pattern is derived
		// from the config directory, so it is on every install and names nothing
		// until a first file is written. What is served is reported beside it,
		// that being what tells an operator which of the two they are looking at.
		detail := fmt.Sprintf("%s, so %s",
			strings.Join(c.Secrets.UnresolvedPatterns, "; "), c.StoreHolds())
		// An entry that could not be searched at all is the exception to the
		// paragraph above: no host waiting for its first secret looks like a
		// directory this account may not read, so there is nothing here to
		// confuse it with. Every managed value is out of the redactor until it
		// is fixed, which is what a file that did not load is failed for.
		if slices.ContainsFunc(c.Secrets.UnresolvedPatterns, keeper.UnresolvedWasRefused) {
			return StatusFailed, detail
		}
		// The guess is only for entries that gave no reason of their own. One
		// that names a directory it could not read has already said why, and
		// being told to go and write a file sends the operator past it.
		if brokercheck.EveryEntryOnlyMissedAMatch(c.Secrets.UnresolvedPatterns) {
			detail += ". Either the secrets have not been written yet, or they " +
				"are on a filesystem that is not mounted"
		}
		return StatusWarn, detail
	case c.Secrets.Count == 0 && len(c.Secrets.Files) == 0:
		// Reachable on an install whose secrets are all linked and whose links have
		// all gone: nothing was read, so there is no file to name.
		return StatusWarn, fmt.Sprintf("no managed file was read and %s produced "+
			"no value, so nothing is injectable and nothing is redacted",
			brokercheck.LinkEntries(c.Secrets.Links))
	case c.Secrets.Count == 0:
		return StatusWarn, fmt.Sprintf("read %s and loaded no refs, so nothing is "+
			"injectable and nothing is redacted",
			strings.Join(c.Secrets.Files, ", "))
	}
	return StatusOK, fmt.Sprintf("%d ref(s) from %d file(s)%s",
		c.Secrets.Count, len(c.Secrets.Files), c.LinkNote())
}

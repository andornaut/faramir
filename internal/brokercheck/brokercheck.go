// Package brokercheck is the report `faramir-broker --check` prints, and the
// questions asked of it.
//
// Two callers read the same report and must not disagree about it: the install
// runs the check to decide whether what it just wrote serves anything, and a
// diagnosis runs it to say whether a host still does. The judgements differ --
// one refuses a run, the other files a finding -- but what counts as a store
// holding nothing, a ref that will not redact, or a link that loaded degraded
// is decided once, here.
package brokercheck

import (
	"fmt"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/keeper"
)

// CheckReport is the part of `faramir-broker --check` this acts on; the rest is
// passed through as the command's own output.
type CheckReport struct {
	Secrets struct {
		Count int `json:"count"`
		// Patterns is the configured globs, Files what they named on disk. Entries
		// naming nothing are a host waiting for its secrets; files that did not
		// load are a fault.
		Patterns []string `json:"patterns"`
		Files    []string `json:"files"`
		Errors   []string `json:"errors"`
		// UnresolvedPatterns is the entries that named nothing, which the broker
		// cannot work out for itself: the secrets directory is the keeper's to
		// list.
		UnresolvedPatterns []string `json:"unresolved_patterns"`
		// NotRedactable is the refs the store read and the redactor refused, by ref
		// and reason. They load and are never injected, so each is a value to
		// lengthen rather than anything about the install.
		NotRedactable map[string]string `json:"not_redactable"`
		// ShadowedRefs is the refs more than one managed file defines with
		// different values, by ref and by which files. The value that lost is on
		// disk and in no redactor, which is what NotRedactable is too, so the two
		// are reported alike.
		ShadowedRefs map[string]string `json:"shadowed_refs"`
		// DegradedLinks is the [[secret.link]] entries that did not load, by ref.
		// Each refuses that ref alone; the broker goes on serving the rest.
		DegradedLinks map[string]string `json:"degraded_links"`
		// Links is how many of Count came from [[secret.link]] entries rather than
		// from a managed file. A count, not the paths, which are the operator's
		// own files. An install whose whole value set is linked keeps no store,
		// and the daemon serves it.
		Links int `json:"links"`
	} `json:"secrets"`
	// Policy is the socket-policy problems, which --check also exits non-zero
	// for. Read here so a caller can tell which reason it is looking at.
	Policy []string `json:"policy"`
}

// refStatesOtherThan reports whether any of the three ref-level states --check
// exits non-zero for is left unaccounted for, each of them being a value this
// host manages that no redactor holds.
//
// It exists because --check exits 1 for several states at once and the exit
// code cannot say which: a caller that has reported one needs to know whether
// anything else is still outstanding. The Only* helpers below answer the same
// question from the other side.
//
// An empty value set is deliberately not among them. It stopped being a
// non-zero exit when the broker started serving one, so counting it here would
// leave a real finding beside it looking unexplained.
func (c CheckReport) refStatesOtherThan(mine int) bool {
	others := 0
	for _, n := range []int{len(c.Secrets.NotRedactable), len(c.Secrets.DegradedLinks),
		len(c.Secrets.ShadowedRefs)} {
		others += n
	}
	return others-mine > 0
}

// OnlyNotRedactable reports whether a non-zero --check is accounted for by refs
// the redactor refused and nothing else. The distinction earns its place
// because this state is not about the install: the store loaded, the daemons
// are serving, and one value is too short to cover.
func (c CheckReport) OnlyNotRedactable() bool {
	return len(c.Secrets.NotRedactable) > 0 &&
		len(c.Policy) == 0 &&
		len(c.Secrets.Errors) == 0 &&
		!c.refStatesOtherThan(len(c.Secrets.NotRedactable))
}

// NoSecretsYet reports whether every configured pattern named no file, which
// is what a first install looks like before the secrets directory is written.
// The running broker refuses to serve, but failing the install over it leaves
// no way to reach a working host.
func (c CheckReport) NoSecretsYet() bool {
	absent := c.Secrets.UnresolvedPatterns
	return len(absent) > 0 && len(absent) == len(c.Secrets.Patterns)
}

// OnlyDegradedLinks reports whether a non-zero --check is accounted for by
// links that did not load and nothing else. Like onlyNotRedactable, this is not
// about the install: the store loaded, the daemons are serving every other ref,
// and what is missing is a file another tool owns and this command cannot
// write.
func (c CheckReport) OnlyDegradedLinks() bool {
	return len(c.Secrets.DegradedLinks) > 0 &&
		len(c.Policy) == 0 &&
		len(c.Secrets.Errors) == 0 &&
		!c.refStatesOtherThan(len(c.Secrets.DegradedLinks))
}

// RefusedRefs is the refused refs and their reasons, ordered, for a message.
func (c CheckReport) RefusedRefs() string {
	return RefsWithReasons(c.Secrets.NotRedactable)
}

// DegradedRefs is the same for the links that did not load.
func (c CheckReport) DegradedRefs() string {
	return RefsWithReasons(c.Secrets.DegradedLinks)
}

func RefsWithReasons(refs map[string]string) string {
	out := make([]string, 0, len(refs))
	for ref, reason := range refs {
		out = append(out, fmt.Sprintf("%s (%s)", ref, reason))
	}
	slices.Sort(out)
	return strings.Join(out, ", ")
}

// Serves reports whether the broker will run exec and redact: something was
// read, and every file it read loaded. Store.Unreadable is the daemon's own
// gate, mirrored here so a probe that runs a brokered command is skipped only
// when it would really be refused.
//
// Links as well as files, because a [[secret.link]] entry fills the value set
// without the keeper contributing anything, and an install whose whole set is
// linked keeps no managed file at all. Counting files alone skipped the probes
// that check redaction on exactly those hosts, and gave the broker refusing as
// the reason when it was serving.
//
// Not a ref count: files that hold nothing still serve, the daemon asking what
// was read rather than what was in it. Configured links rather than resolved
// ones, which the report does not carry: a link whose file has gone reads as
// serving here and the probe then fails on it, which names the fault. The other
// direction skips the probe and reports nothing.
// Serves reports whether the broker will run a brokered command at all, which
// is what the probes that send one are gated on. An empty value set is not a
// refusal: it holds no value for output to carry, so the command runs and comes
// back redacted against nothing. What refuses is a managed file that was found
// and did not load.
func (c CheckReport) Serves() bool {
	return len(c.Secrets.Errors) == 0
}

// StoreHolds is what the value set is made of beside an entry that named no
// file, which is what separates a host keeping its secrets in links alone, or
// in the files another entry did name, from one whose store went missing.
//
// Serving nothing is the last case and not the default: the daemon refuses exec
// and redact on a store where no managed file loaded and nothing is linked, so
// one entry naming nothing while another resolved is a value set that is served
// and must not be described as one that is not.
func (c CheckReport) StoreHolds() string {
	switch {
	case c.Secrets.Links > 0 && c.Secrets.Count > c.Secrets.Links:
		return fmt.Sprintf("%d ref(s) are served, %d of them from %s",
			c.Secrets.Count, c.Secrets.Links, LinkEntries(c.Secrets.Links))
	case c.Secrets.Links > 0:
		return "the whole value set is " + LinkEntries(c.Secrets.Links)
	// A file that loaded and held nothing still opens the gate, which is on a
	// managed file having been read and not on how many refs came out of it, so
	// this is neither a store that serves values nor one that refuses the ops.
	case len(c.Secrets.Files) > 0 && c.Secrets.Count == 0:
		return fmt.Sprintf("%d file(s) loaded and held no ref, so nothing is "+
			"injected and nothing is redacted", len(c.Secrets.Files))
	case len(c.Secrets.Files) > 0:
		return fmt.Sprintf("%d ref(s) are served from %d file(s)",
			c.Secrets.Count, len(c.Secrets.Files))
	}
	return "nothing is injected and nothing is redacted"
}

// LinkNote names the linked share of a value set that also has managed files,
// so a count that changed says which half it changed in.
func (c CheckReport) LinkNote() string {
	if c.Secrets.Links == 0 {
		return ""
	}
	return " and " + LinkEntries(c.Secrets.Links)
}

func LoadErrorDetail(errors []string) string {
	if len(errors) == 0 {
		return "The broker reported no load error, so the file parsed and is empty " +
			"rather than unreadable."
	}
	return "Load errors: " + strings.Join(errors, "; ")
}

// EveryEntryOnlyMissedAMatch reports whether nothing stopped the search: each
// entry looked where it was told and found no file there.
func EveryEntryOnlyMissedAMatch(entries []string) bool {
	for _, entry := range entries {
		if !strings.HasSuffix(entry, keeper.NoMatchReason) {
			return false
		}
	}
	return true
}

// LinkEntries names a count of link entries, singular where there is one: this
// reads in the middle of a sentence an operator is being told something by.
func LinkEntries(n int) string {
	if n == 1 {
		return "1 [[secret.link]] entry"
	}
	return fmt.Sprintf("%d [[secret.link]] entries", n)
}

package audit

// The reductions that make a record fit its cap, and what is written when none
// of them do.  See the package doc in audit.go for the guarantee this serves:
// one record is one line, and no line exceeds [config.AuditConfig]
// MaxRecordBytes.

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"

	"github.com/andornaut/faramir/internal/config"
)

// reductions are what encode falls back through when a record does not fit,
// each a ceiling on one string and on how many entries a list or a map keeps.
// Both are needed: a record can be too large because one field is long (argv
// holding a generated `--extra-vars` blob) or because there are many of them
// (an env_refs map naming the same value under a thousand names), and cutting
// only strings leaves the second case unreachable by any ceiling.
//
// Deliberately few, and each a long way below the last: this runs on a record
// that is already over the cap, and an operator reading one wants to know it was
// reduced, not to receive it exactly at the limit.
var reductions = [][2]int{{fieldCeiling, 64}, {256, 8}, {64, 4}}

// encode is one record as one line, never longer than the cap.  It reduces
// rather than gives up, because what is over the cap is almost always one
// caller-chosen field and the rest of the record is the part being audited.
func (l *Log) encode(payload map[string]any) []byte {
	limit := config.MaxRecordBytes
	line, err := json.Marshal(payload)
	if err == nil && len(line)+1 <= limit {
		return append(line, '\n')
	}
	if err != nil {
		log.Printf("audit marshal failed: %v", err)
	} else {
		before, _ := payload["output"].(string)
		for _, step := range reductions {
			// Each field, not the record.  reduce() bounds how many entries a
			// collection keeps, so applied to the payload itself that ceiling would
			// bound the record's own fields: it keeps the first entries in sorted key
			// order, which drops `redactions` -- what says which credentials the
			// command used -- and leaves a line that reads as an ordinary complete
			// record.  The field set is the code's, not a caller's, and is never what
			// is too large.
			for key, value := range payload {
				payload[key] = reduce(value, step[0], step[1])
			}
			payload["record_reduced"] = true
			// The output field is reduced along with the rest, so what it says about
			// itself has to keep up: a record whose output was cut and does not say so
			// reads as a complete one.
			//
			// Whether it changed, not whether it shrank.  clamp counts in encoded bytes
			// and appends a marker, so an output of escape-heavy bytes comes back longer
			// in raw ones than it went in, and a length test reads that as untouched.
			// What went is measured against the marker taken back off, for the same
			// reason.
			if after, _ := payload["output"].(string); after != before {
				payload["output_truncated"] = true
				dropped, _ := payload["output_dropped"].(int)
				kept := strings.TrimSuffix(after, clampMarker)
				payload["output_dropped"] = dropped + max(len(before)-len(kept), 0)
				before = after
			}
			if line, err = json.Marshal(payload); err == nil && len(line)+1 <= limit {
				return append(line, '\n')
			}
		}
	}
	return l.lastResort(payload, len(payload))
}

// strict makes reaching the last resort fatal instead of survivable.  Tests set
// it, so a change that puts a record beyond the cap stops CI on the spot rather
// than being noticed later in a log; the two tests that reach it deliberately
// turn it off around themselves.
//
// Off in the shipped binary on purpose.  Reaching this is a bug, and a bug is
// worth crashing on where a crash costs nothing -- but here it would take the
// broker down mid-run, killing every brokered command with it, to protect a
// record it was already about to write.  On a host the answer is to write the
// record and say, in terms nobody reads past, that this build is wrong.
var strict = false

// lastResort is what happens when a record cannot be made to fit: it is written
// cut back to the fact that it happened, and the fact that it happened is a bug
// reported in the same breath.
//
// Not caller-controlled and so not a runtime condition to handle.  Everything a
// caller chooses -- how long a value is, how many entries a list holds -- is
// bounded by the reductions above.  What is left is the record's *field set*
// against [config.AuditConfig] MaxRecordBytes, and the field set is written in
// this repository: a record grew fields, or a value of a type that will not
// marshal was put in one.  Either is a change somebody made here, and
// TestEveryRecordThisTreeWritesFitsTheSmallestCap fails on the first of them
// before it can ship.
//
// It still writes the line rather than dropping it or refusing.  Being a bug
// does not make the record less true, and a host that has this bug is a host
// where something ran.
func (l *Log) lastResort(payload map[string]any, fields int) []byte {
	// Named short and quoted: by here the op has been through the reductions like
	// everything else, so it is not necessarily the word the record started with.
	op := fmt.Sprint(payload["op"])
	if len(op) > 32 {
		op = op[:32] + "…"
	}
	report := fmt.Sprintf("BUG in faramir: a %d-field %q record does not fit "+
		"the record cap (%d) even reduced, so it is being written as its "+
		"identity alone. Every record of this shape is affected, not this one. "+
		"Either a record gained fields without config.MinRecordBytes being raised "+
		"to match, or one carries a value that will not marshal",
		fields, op, config.MaxRecordBytes)
	if strict {
		panic(report)
	}
	log.Print(report)
	return stubLine(payload)
}

// stubLine is the record cut back to its identity.  It is what makes encode
// total -- for any input there is a line, and it is under the cap -- so no
// caller has to hold an opinion about what to do when there is not.
func stubLine(payload map[string]any) []byte {
	const why = "this record did not fit the record cap and was reduced to its identity"
	// Printed and clamped rather than carried across as they stand.  One route
	// here is the first marshal failing, which skips the reductions entirely, so
	// these three were never bounded and a line built from them would be as long
	// as they are -- the one thing this function exists to rule out.  Printing
	// them also leaves the map holding strings and a bool, neither of which can
	// fail to marshal, so there is no second failure to fall back from.
	line, err := json.Marshal(map[string]any{
		"log_id":         clamp(fmt.Sprint(payload["log_id"]), 256),
		"op":             clamp(fmt.Sprint(payload["op"]), 256),
		"peer":           clamp(fmt.Sprint(payload["peer"]), 256),
		"error":          why,
		"record_reduced": true,
	})
	if err != nil || len(line) == 0 {
		// Unreachable, and the belt to the braces: the invariant is that this
		// function returns a record, so it does not depend on being right about that.
		line = []byte(`{"error":"` + why + `"}`)
	}
	return append(line, '\n')
}

// reduce cuts every string in the record to strLimit encoded bytes and every list
// and map to items entries, saying so where it does.  It walks what a record is
// made of rather than naming fields, so a field added later is bounded without
// this having to hear about it.
//
// Encoded bytes, not raw ones: the cap this serves is counted in what the line
// spends, so a ceiling counted any other way is a ceiling in the wrong unit --
// two hundred arguments of a thousand '<' each are 200KB raw, under any
// per-string limit worth having, and 1.2MB once encoded.
//
// Every collection it returns is a new one, and none of the ones it is given is
// written through.  A record's fields are the caller's own live state -- the
// escalation server hands over the argv it holds for a run, and goes on rendering
// that argv into the question, the refusal messages and every later record -- so
// a reduction that clamped a string in place would cut the caller's copy of it
// too.  Recording something must not change it.
func reduce(value any, strLimit, items int) any {
	switch typed := value.(type) {
	case string:
		return clamp(typed, strLimit)
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, inner := range typed {
			out[key] = reduce(inner, strLimit, items)
		}
		return dropEntries(out, items)
	case map[string]string:
		out := make(map[string]string, len(typed))
		for key, inner := range typed {
			out[key] = clamp(inner, strLimit)
		}
		return dropEntries(out, items)
	case []string:
		out := make([]string, len(typed))
		for i, inner := range typed {
			out[i] = clamp(inner, strLimit)
		}
		if len(out) > items {
			return append(out[:items:items], more(len(out)-items))
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, inner := range typed {
			out[i] = reduce(inner, strLimit, items)
		}
		if len(out) > items {
			return append(out[:items:items], any(more(len(out)-items)))
		}
		return out
	default:
		return reduceTyped(value, strLimit, items)
	}
}

// reduceTyped bounds a slice whose element type this package cannot name.
// `redactions` is []redact.Count, and naming it here would make the audit log
// depend on the redactor to know how large it may be; more to the point, the
// next such field would need the same edit, and the promise above is that it
// would not.  Reflection is the price of that promise, and it is paid only on a
// record already over the cap.
//
// The result is []any, so the marker can sit in it: a list of objects that ends
// in a sentence is odd to look at and says what happened, which a list silently
// missing 19,000 entries does not.
func reduceTyped(value any, strLimit, items int) any {
	if value == nil {
		return value
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Slice || rv.Len() <= items {
		return value
	}
	out := make([]any, 0, items+1)
	for i := range items {
		out = append(out, reduce(rv.Index(i).Interface(), strLimit, items))
	}
	return append(out, any(more(rv.Len()-items)))
}

// clampMarker is what clamp leaves in place of what it cut.  Named so a caller
// counting what went can take it back off: it is appended, so a cut string is
// not necessarily shorter than the one it replaced.
const clampMarker = "… (cut to fit the record)"

// clamp is one string at an encoded ceiling, marked where it was cut.
func clamp(text string, budget int) string {
	if encodedLen(text) <= budget {
		return text
	}
	return prefixWithin(text, max(budget-markerReserve, 1)) + clampMarker
}

func more(n int) string { return fmt.Sprintf("… (%d more, cut to fit the record)", n) }

// dropEntries keeps the first items keys in sorted order, so which entries
// survive is the same on every run rather than whatever the map iterated to
// first.  A map is generic over its value type, so this is written twice rather
// than reached through reflection.
//
// It deletes in place, and is called only on a map reduce has just built, so
// what it edits is nobody else's.
func dropEntries[V any](entries map[string]V, items int) map[string]V {
	if len(entries) <= items {
		return entries
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys[items:] {
		delete(entries, key)
	}
	return entries
}

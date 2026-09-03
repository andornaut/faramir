package audit

// The reductions that make a record fit its cap, and what is written when none
// of them do. See the package doc in audit.go for the guarantee this serves:
// one record is one line, and no line exceeds config.MaxRecordBytes.

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
// Both are needed: a record can be too large because one field is long or
// because there are many of them, and cutting only strings leaves the second
// case unreachable. Deliberately few, and each a long way below the last.
var reductions = [][2]int{{fieldCeiling, 64}, {256, 8}, {64, 4}}

// encode is one record as one line, never longer than the cap. It reduces
// rather than gives up: what is over the cap is almost always one
// caller-chosen field, and the rest of the record is the part being audited.
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
			// Each field, not the record: reduce bounds how many entries a collection
			// keeps, so applied to the payload it would drop the record's own fields
			// in sorted key order, `redactions` among them, and leave a line that
			// reads as complete. The field set is the code's and is never what is
			// too large.
			for key, value := range payload {
				payload[key] = reduce(value, step[0], step[1])
			}
			payload["record_reduced"] = true
			// The output field is reduced along with the rest, so what it says about
			// itself has to keep up. Whether it changed, not whether it shrank: clamp
			// counts in encoded bytes and appends a marker, so escape-heavy output
			// comes back longer in raw bytes than it went in. What went is measured
			// with the marker taken back off.
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

// strict makes reaching the last resort fatal instead of survivable. Tests set
// it, so a change that puts a record beyond the cap stops CI rather than being
// noticed later in a log. Off in the shipped binary: a panic here would take
// the broker down mid-run, killing every brokered command with it, to protect a
// record it was about to write.
var strict = false

// lastResort is what happens when a record cannot be made to fit: it is written
// cut back to the fact that it happened, and reported as a bug in the same
// breath.
//
// Not caller-controlled: everything a caller chooses is bounded by the
// reductions above, so what is left is the record's own field set against
// config.MaxRecordBytes. A record grew fields, or one carries a value that will
// not marshal, and both are changes made in this repository.
//
// It still writes the line: being a bug does not make the record less true, and
// a host that has this bug is a host where something ran.
func (l *Log) lastResort(payload map[string]any, fields int) []byte {
	// Named short and quoted: by here the op has been through the reductions, so
	// it is not necessarily the word the record started with.
	op := fmt.Sprint(payload["op"])
	if len(op) > 32 {
		op = op[:32] + "…"
	}
	report := fmt.Sprintf("BUG in faramir: a %d-field %q record does not fit "+
		"the record cap (%d) even after reduction, so only its identity is "+
		"written. Every record of this shape is affected. Either a field was "+
		"added without raising config.MinRecordBytes, or a value does not marshal",
		fields, op, config.MaxRecordBytes)
	if strict {
		panic(report)
	}
	log.Print(report)
	return stubLine(payload)
}

// stubLine is the record cut back to its identity. It is what makes encode
// total: for any input there is a line, and it is under the cap.
func stubLine(payload map[string]any) []byte {
	const why = "this record did not fit the record cap and was reduced to its identity"
	// Printed and clamped rather than carried across as they stand: one route
	// here is the first marshal failing, which skips the reductions, so these
	// three were never bounded. Printing them also leaves the map holding
	// strings and a bool, neither of which can fail to marshal.
	line, err := json.Marshal(map[string]any{
		"log_id":         clamp(fmt.Sprint(payload["log_id"]), 256),
		"op":             clamp(fmt.Sprint(payload["op"]), 256),
		"peer":           clamp(fmt.Sprint(payload["peer"]), 256),
		"error":          why,
		"record_reduced": true,
	})
	if err != nil || len(line) == 0 {
		// Unreachable: the invariant is that this function returns a record, so it
		// does not depend on being right about that.
		line = []byte(`{"error":"` + why + `"}`)
	}
	return append(line, '\n')
}

// reduce cuts every string in the record to strLimit encoded bytes and every
// list and map to items entries, saying so where it does. It walks what a
// record is made of rather than naming fields, so a field added later is
// bounded without this having to hear about it.
//
// Encoded bytes, not raw ones: the cap this serves is counted in what the line
// spends. Two hundred arguments of a thousand '<' each are 200KB raw and 1.2MB
// once encoded.
//
// Every collection it returns is a new one: a record's fields are the caller's
// own live state -- the escalation server hands over the argv it holds for a
// run and goes on rendering it into the question -- so clamping a string in
// place would cut the caller's copy too.
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
// depend on the redactor, and the next such field would need the same edit.
// Reflection is paid only on a record already over the cap.
//
// The result is []any, so the marker can sit in it: a list that ends in a
// sentence says what happened, which one silently missing entries does not.
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

// clampMarker is what clamp leaves in place of what it cut. Named so a caller
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
// survive is the same on every run. It deletes in place, and is called only on
// a map reduce has just built.
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

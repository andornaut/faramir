package audit

import (
	"strings"
	"testing"
)

// One record's line is capped, and internal/audit cuts every field to fit
// rather than failing to write one. So whatever a command printed, the excerpt
// is inside the budget it was given.
func FuzzAnExcerptStaysInsideItsBudget(f *testing.F) {
	// Budgets inside the range the property is stated over: below 256 the seed
	// takes the skip below and the corpus asserts nothing under `go test`.
	f.Add("hello", 256)
	f.Add("\x00\x01\x02 binary", 256)
	// Longer than its budget, so the seeds reach the excerpting itself rather
	// than only the path that hands the whole output back.
	f.Add(strings.Repeat("x", 4096), 256)

	f.Fuzz(func(t *testing.T, output string, budget int) {
		// Above the marker's own cost: below that the marker alone is over the
		// budget, which is an edge of the arithmetic rather than of the excerpt,
		// and no caller gets there (the record cap is 256 KiB).
		if budget < 256 || budget > 1<<20 {
			t.Skip()
		}
		text, dropped := excerpt(output, budget)
		if dropped < 0 {
			t.Fatalf("dropped %d bytes", dropped)
		}
		// excerpt hands back the whole output where cutting it would not be
		// shorter, so the budget binds only what it actually excerpted.
		if text != output && encodedLen(text) > budget {
			t.Fatalf("an excerpt of %d encoded bytes came back for a budget of %d", encodedLen(text), budget)
		}
		if dropped > 0 && text == output {
			t.Fatalf("reported %d bytes dropped and returned the whole output", dropped)
		}
	})
}

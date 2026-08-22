package protocol_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	faramir "github.com/andornaut/faramir"
	"github.com/andornaut/faramir/internal/protocol"
)

// docTable is the "Op | Does | Notes" table of docs/protocol.md, read from the
// embedded copy rather than the working tree: that is the one an install writes
// out, and so the one whoever is writing a client has.
func docTable(t *testing.T) []string {
	t.Helper()
	body, err := faramir.Assets.ReadFile("docs/protocol.md")
	if err != nil {
		t.Skipf("the protocol doc is not embedded here: %v", err)
	}
	text := string(body)
	start := strings.Index(text, "Op | Does | Notes")
	if start < 0 {
		t.Fatal("the protocol doc carries no op table, so this asserts nothing")
	}
	table := text[start:]
	if end := strings.Index(table, "\n\n"); end > 0 {
		table = table[:end]
	}
	var ops []string
	for line := range strings.SplitSeq(table, "\n") {
		if m := regexp.MustCompile("^`([a-z]+)` \\|").FindStringSubmatch(line); m != nil {
			ops = append(ops, m[1])
		}
	}
	if len(ops) == 0 {
		t.Fatal("no rows parsed out of the op table, so this asserts nothing")
	}
	return ops
}

// The op table is where a client author finds out what the socket takes. An op
// the broker accepts and the table omits is one nothing tells them about, and a
// row for an op the broker refuses sends them to write against something that
// is not there: an unknown op is refused rather than defaulted, so the second
// is a client that fails on its first call.
func TestTheOpTableListsExactlyTheOpsTheBrokerTakes(t *testing.T) {
	documented := docTable(t)
	accepted := append([]string{}, protocol.Ops...)
	slices.Sort(documented)
	slices.Sort(accepted)
	if !slices.Equal(documented, accepted) {
		t.Errorf("the op table lists %v, the broker takes %v", documented, accepted)
	}
}

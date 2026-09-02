package termui

import (
	"strings"
	"testing"
)

// A path has to stay copyable, so an over-long one overflows.
func TestAnOverlongWordIsNotSplit(t *testing.T) {
	path := "/very/" + strings.Repeat("long/", 30) + "config.toml"
	if lines := Wrap(path, 40); len(lines) != 1 || lines[0] != path {
		t.Errorf("split a single word into %d lines", len(lines))
	}
}

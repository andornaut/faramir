package main

import "testing"

func TestShareRequiresExplicitDirectoryAndGroup(t *testing.T) {
	for _, args := range [][]string{nil, {"--group", "dev"}, {"/some/tree"}, {"--group", "", "/some/tree"}} {
		if got := runCommand(newShareCmd(), args); got != 2 {
			t.Errorf("share %q = %d, want usage error", args, got)
		}
	}
}

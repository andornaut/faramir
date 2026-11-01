package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/cli"
)

func TestUnenrolHelpAndOperatorClassification(t *testing.T) {
	c := newUnenrolCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetArgs([]string{"--help"})
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"unenrol", "--dry-run", "--json", "filesystem sharing", "fresh agent sessions"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help omits %q", want)
		}
	}
	found := false
	for _, name := range cli.OperatorOnly() {
		found = found || name == "unenrol"
	}
	if !found || c.GroupID != groupOperator {
		t.Fatal("unenrol is not operator-only")
	}
	if err := c.Args(c, []string{"one", "two"}); err == nil {
		t.Fatal("accepted more than one directory")
	}
}

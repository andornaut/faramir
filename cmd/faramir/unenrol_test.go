package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/cli"
	"github.com/andornaut/faramir/internal/enrol"
)

func TestUnenrolHelpAndOperatorClassification(t *testing.T) {
	c := newUnenrolCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetArgs([]string{"--help"})
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"unenrol", "--dry-run", "--json", "--missing", "filesystem sharing", "fresh agent sessions"} {
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

func TestUnenrolMissingRejectsEveryDirectoryArgument(t *testing.T) {
	c := newUnenrolCmd()
	if err := c.Flags().Set("missing", "true"); err != nil {
		t.Fatal(err)
	}
	if err := c.Args(c, nil); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"."}, {"one", "two"}} {
		if err := c.Args(c, args); err == nil {
			t.Fatalf("--missing accepted directories: %v", args)
		}
	}
}

func TestUnenrolMissingSummaryAndJSONChangedContract(t *testing.T) {
	for _, tc := range []struct {
		report enrol.UnenrolReport
		want   string
	}{
		{enrol.UnenrolReport{Bulk: true, RecordOnly: true}, "no missing enrolment records"},
		{enrol.UnenrolReport{Dir: "/missing/project", RecordOnly: true}, "no enrolment record for missing project /missing/project"},
		{enrol.UnenrolReport{RecordOnly: true, MissingRecords: []string{"/gone"}}, "forgot 1 missing enrolment record(s)"},
		{enrol.UnenrolReport{Bulk: true, RecordOnly: true, DryRun: true, MissingRecords: []string{"/gone"}}, "dry run: would forget 1 missing enrolment record(s)"},
		{enrol.UnenrolReport{Dir: "/existing/project"}, "unenrolled /existing/project"},
	} {
		if got := unenrolSummary(tc.report); got != tc.want {
			t.Errorf("summary = %q, want %q", got, tc.want)
		}
	}
	for _, changed := range []bool{false, true} {
		report := enrol.UnenrolReport{Bulk: true, RecordOnly: true}
		report.Record("missing enrolment", changed, "fixture")
		body, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatal(err)
		}
		if doc["changed"] != changed || doc["bulk"] != true || doc["dir"] != "" {
			t.Fatalf("existing report fields changed type or disappeared: %s", body)
		}
	}
}

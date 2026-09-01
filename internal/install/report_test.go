package install

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/steps"
)

// The report is a documented interface: `--json` is what a configuration
// manager reads instead of stat-ing the host, and the fields it reads are named
// here rather than in the struct it happens to be built from. Report embeds
// steps.Report, and an embedded struct is inlined by encoding/json, so a change
// from embedding to a named field would rename every one of these without
// touching a tag. internal/enroll holds the same test for its own report.
func TestTheReportSerialisesTheFieldsItPromises(t *testing.T) {
	body, err := json.Marshal(Report{Version: "v", Steps: []steps.Step{{Name: "s"}}})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "changed", "steps"} {
		if _, ok := got[key]; !ok {
			t.Errorf("%q is not in the report: %s", key, body)
		}
	}
	// The optional ones stay out when they are empty, or every run reports
	// warnings it does not have.
	for _, key := range []string{"warnings", "dry_run"} {
		if _, ok := got[key]; ok {
			t.Errorf("%q is present on a report that has none: %s", key, body)
		}
	}
}

// Every step a run reports has a name, and no two share one: a report reads as
// a list of blanks otherwise, and an error naming a step is ambiguous. Per
// command, the two commands being free to use the same name for the same work.
func TestEveryStepIsNamedAndRunsSomething(t *testing.T) {
	list := (&runner{}).steps()
	if len(list) == 0 {
		t.Fatal("the command has no steps")
	}
	seen := map[string]bool{}
	for i, s := range list {
		if strings.TrimSpace(s.Name) == "" {
			t.Errorf("step %d has no name", i)
		}
		if s.Run == nil {
			t.Errorf("step %q runs nothing", s.Name)
		}
		if seen[s.Name] {
			t.Errorf("two steps are called %q, so an error naming one is ambiguous", s.Name)
		}
		seen[s.Name] = true
	}
}

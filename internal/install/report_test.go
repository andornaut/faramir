package install

import (
	"encoding/json"
	"slices"
	"testing"
)

// Both reports are a documented interface: `--json` is what a configuration
// manager reads instead of stat-ing the host, and the fields it reads are
// named here rather than in the struct it happens to be built from. Report and
// ProjectReport embed runReport, and an embedded struct is inlined by
// encoding/json, so a change from embedding to a named field would rename every
// one of these without touching a tag.
func TestTheReportsSerialiseTheFieldsTheyPromise(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		want  []string
	}{
		{
			"init",
			Report{Version: "v", runReport: runReport{Steps: []Step{{Name: "s"}}}},
			[]string{"version", "changed", "steps"},
		},
		{
			"init-project",
			ProjectReport{Version: "v", Dir: "/d", ClientGroup: "g", runReport: runReport{
				Steps: []Step{{Name: "s"}},
			}},
			[]string{"version", "dir", "group", "changed", "steps"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatal(err)
			}
			for _, key := range tc.want {
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
		})
	}
}

// One step per unit of work, and Changed is what says a run did something.
func TestAStepMarksTheReportChanged(t *testing.T) {
	var report runReport
	report.step("first", false, "")
	report.step("second", true, "detail")
	report.skip("third", "dry run")

	if !report.Changed {
		t.Error("a step that changed something left the report unchanged")
	}
	if len(report.Steps) != 3 {
		t.Fatalf("recorded %d steps, want 3", len(report.Steps))
	}
	if !report.Steps[2].Skipped {
		t.Error("a skipped step is not marked skipped")
	}
	// A skip is not a change.
	var quiet runReport
	quiet.skip("only", "dry run")
	if quiet.Changed {
		t.Error("a skipped step marked the report changed")
	}
}

// Every step a run reports has a name, or a report reads as a list of blanks.
func TestEveryStepInBothCommandsIsNamed(t *testing.T) {
	steps := (&runner{}).steps()
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.name)
	}
	for _, step := range (&project{}).steps() {
		names = append(names, step.name)
	}
	if len(names) == 0 {
		t.Fatal("neither command has any steps")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" {
			t.Error("a step has no name")
		}
		if seen[name] && !slices.Contains([]string{"agent config"}, name) {
			t.Errorf("two steps are called %q", name)
		}
		seen[name] = true
	}
}

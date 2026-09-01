package steps

import "testing"

// One step per unit of work, and Changed is what says a run did something.
func TestAStepMarksTheReportChanged(t *testing.T) {
	var report Report
	report.Record("first", false, "")
	report.Record("second", true, "detail")
	report.Skip("third", "dry run")

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
	var quiet Report
	quiet.Skip("only", "dry run")
	if quiet.Changed {
		t.Error("a skipped step marked the report changed")
	}
}

// The log is a side channel and no part of the document: a report that carries
// one has to serialise the same as a report that does not.
func TestTheLogIsNoPartOfWhatIsRecorded(t *testing.T) {
	var lines []string
	var report Report
	report.LogTo(func(line string) { lines = append(lines, line) })
	report.Record("first", true, "detail")
	report.Skip("second", "dry run")

	if len(lines) != 2 {
		t.Fatalf("logged %d lines, want 2: %v", len(lines), lines)
	}
	if len(report.Steps) != 2 {
		t.Errorf("recorded %d steps, want 2", len(report.Steps))
	}
}

// Warnings are the things that install cleanly and then do not work, so they
// are collected rather than returned.
func TestAWarningIsRecordedWithoutFailingTheRun(t *testing.T) {
	var report Report
	report.Warnf("%s is not there", "/srv/gone")
	if len(report.Warnings) != 1 || report.Warnings[0] != "/srv/gone is not there" {
		t.Errorf("warnings = %v", report.Warnings)
	}
	if report.Changed {
		t.Error("a warning marked the report changed")
	}
}

// A count of nothing is left off: a step that asserted a tree and one that
// rewrote it must not read alike.
func TestDetailWithCountNamesOnlyWhatChanged(t *testing.T) {
	if got, want := DetailWithCount("/srv/tree", 0), "/srv/tree"; got != want {
		t.Errorf("DetailWithCount(_, 0) = %q, want %q", got, want)
	}
	if got := DetailWithCount("/srv/tree", 3); got == "/srv/tree" {
		t.Errorf("DetailWithCount(_, 3) = %q, which does not say what changed", got)
	}
}

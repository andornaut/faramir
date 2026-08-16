package main

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/andornaut/faramir/internal/install"
)

// The report is read by someone looking for the one line that is not "ok".

func TestTheStatusColumnIsFixedAndTheDetailAligns(t *testing.T) {
	var out bytes.Buffer
	printDiagnosis(&out, palette{}, install.DoctorReport{Findings: []install.Finding{
		{Name: "config", Status: install.StatusOK, Detail: "/etc/faramir/config.toml"},
		{Name: "age key", Status: install.StatusFailed, Detail: "readable by andornaut"},
	}})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected a line per finding:\n%s", out.String())
	}
	// The detail starts at the same column on both.
	first := strings.Index(lines[0], "/etc/faramir")
	second := strings.Index(lines[1], "readable")
	if first != second {
		t.Errorf("details start at %d and %d:\n%s", first, second, out.String())
	}
}

func TestARepeatedCheckIsNamedOnce(t *testing.T) {
	var out bytes.Buffer
	printDiagnosis(&out, palette{}, install.DoctorReport{Findings: []install.Finding{
		{Name: "sockets", Status: install.StatusOK, Detail: "keeper is listening"},
		{Name: "sockets", Status: install.StatusOK, Detail: "broker is listening"},
	}})
	if got := strings.Count(out.String(), "sockets"); got != 1 {
		t.Errorf("named the check %d times, want 1:\n%s", got, out.String())
	}
	// Named once, but still one line each.
	if got := strings.Count(out.String(), "is listening"); got != 2 {
		t.Errorf("printed %d answers, want 2:\n%s", got, out.String())
	}
}

func TestTheCountsAreReported(t *testing.T) {
	var out bytes.Buffer
	printDiagnosis(&out, palette{}, install.DoctorReport{Findings: []install.Finding{
		{Name: "a", Status: install.StatusOK},
		{Name: "b", Status: install.StatusOK},
		{Name: "c", Status: install.StatusWarn},
		{Name: "d", Status: install.StatusFailed},
	}})
	if !strings.Contains(out.String(), "2 ok, 1 warn, 1 failed") {
		t.Errorf("no summary:\n%s", out.String())
	}
}

// n/a is its own total.  Folded into the ok count it would read as a host that
// passed a check it never had, which is the reason the status exists.
func TestNotApplicableIsCountedApartFromAPass(t *testing.T) {
	var out bytes.Buffer
	printDiagnosis(&out, palette{}, install.DoctorReport{Findings: []install.Finding{
		{Name: "sudo credential", Status: install.StatusOK},
		{Name: "sudo grant", Status: install.StatusNA},
		{Name: "ptrace scope", Status: install.StatusNA},
	}})
	if !strings.Contains(out.String(), "1 ok, 2 n/a") {
		t.Errorf("no summary telling the two apart:\n%s", out.String())
	}
}

// Every status keeps the detail in the same column, or a report is read by
// scanning a ragged edge.
func TestNotApplicableAlignsWithEveryOtherStatus(t *testing.T) {
	for _, locale := range []string{"C.UTF-8", "C"} {
		t.Setenv("LC_ALL", locale)
		t.Setenv("LC_CTYPE", "")
		t.Setenv("LANG", "")
		var out bytes.Buffer
		printDiagnosis(&out, palette{}, install.DoctorReport{Findings: []install.Finding{
			{Name: "x", Status: install.StatusOK, Detail: "detail"},
			{Name: "x", Status: install.StatusNA, Detail: "detail"},
			{Name: "x", Status: install.StatusWarn, Detail: "detail"},
			{Name: "x", Status: install.StatusFailed, Detail: "detail"},
		}})
		// Counted in columns rather than bytes: the glyphs are not all one byte
		// wide, and it is the screen the detail lines up on.
		column := func(line string) int {
			before, _, found := strings.Cut(line, "detail")
			if !found {
				t.Fatalf("no detail on the line:\n%s", line)
			}
			return utf8.RuneCountInString(before)
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")[:4]
		for _, line := range lines[1:] {
			if column(line) != column(lines[0]) {
				t.Errorf("LC_ALL=%s: columns do not line up:\n%s", locale, out.String())
			}
		}
	}
}

func TestALongDetailWrapsUnderItself(t *testing.T) {
	t.Setenv("COLUMNS", "60")
	t.Setenv("LC_ALL", "C.UTF-8")
	var out bytes.Buffer
	printDiagnosis(&out, palette{}, install.DoctorReport{Findings: []install.Finding{
		{Name: "broker", Status: install.StatusWarn, Detail: strings.Repeat("word ", 40)},
	}})
	for line := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
		if width := utf8.RuneCountInString(line); width > 60 {
			t.Errorf("line is %d columns wide:\n%s", width, line)
		}
	}
	// Continuations indent to where the detail started.
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	start := strings.Index(lines[0], "word")
	for _, line := range lines[1 : len(lines)-2] {
		if strings.Index(line, "word") != start {
			t.Errorf("continuation is not aligned with the detail:\n%s", out.String())
		}
	}
}

// A path has to stay copyable, so an over-long one overflows.
func TestAnOverlongWordIsNotSplit(t *testing.T) {
	path := "/very/" + strings.Repeat("long/", 30) + "config.toml"
	if lines := wrapText(path, 40); len(lines) != 1 || lines[0] != path {
		t.Errorf("split a single word into %d lines", len(lines))
	}
}

// The glyph makes the column scannable, the word survives a pipe into a log.
func TestTheStatusCarriesAGlyphAndTheWord(t *testing.T) {
	t.Setenv("LC_ALL", "C.UTF-8")
	var out bytes.Buffer
	printDiagnosis(&out, palette{}, install.DoctorReport{Findings: []install.Finding{
		{Name: "config", Status: install.StatusOK},
		{Name: "age key", Status: install.StatusFailed},
	}})
	for _, want := range []string{"\u2713 ok", "\u2717 failed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in:\n%s", want, out.String())
		}
	}
}

// A non-UTF-8 terminal gets the word alone.
func TestWithoutAUnicodeLocaleTheWordStandsAlone(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "")
	var out bytes.Buffer
	printDiagnosis(&out, palette{}, install.DoctorReport{Findings: []install.Finding{
		{Name: "config", Status: install.StatusOK, Detail: "/etc/faramir/config.toml"},
		{Name: "age key", Status: install.StatusFailed, Detail: "readable by andornaut"},
	}})
	if strings.ContainsAny(out.String(), "\u2713\u2717") {
		t.Errorf("printed a glyph under a non-UTF-8 locale:\n%s", out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if strings.Index(lines[0], "/etc") != strings.Index(lines[1], "readable") {
		t.Errorf("the columns do not line up without the glyph:\n%s", out.String())
	}
}

package main

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/andornaut/faramir/internal/install"
)

// The report is read by a person looking for the one line that is not "ok", so
// what the layout has to do is put the status where the eye lands and keep a
// sentence readable at the width it is being read in.

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
	// The detail starts at the same column on both, which is what makes a
	// column of statuses scannable rather than a ragged list.
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
	// Named once, but still one line each: the second answer is its own finding
	// and hiding it would lose which socket is which.
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

func TestALongDetailWrapsUnderItself(t *testing.T) {
	t.Setenv("COLUMNS", "60")
	t.Setenv("LC_ALL", "C.UTF-8")
	var out bytes.Buffer
	printDiagnosis(&out, palette{}, install.DoctorReport{Findings: []install.Finding{
		{Name: "broker", Status: install.StatusWarn, Detail: strings.Repeat("word ", 40)},
	}})
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if width := utf8.RuneCountInString(line); width > 60 {
			t.Errorf("line is %d columns wide:\n%s", width, line)
		}
	}
	// Every continuation is indented to where the detail started, so the
	// leftmost column stays nothing but statuses.
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	start := strings.Index(lines[0], "word")
	for _, line := range lines[1 : len(lines)-2] {
		if strings.Index(line, "word") != start {
			t.Errorf("continuation is not aligned with the detail:\n%s", out.String())
		}
	}
}

// A path is one word and has to stay copyable, so an over-long one overflows
// rather than being broken across two lines.
func TestAnOverlongWordIsNotSplit(t *testing.T) {
	path := "/very/" + strings.Repeat("long/", 30) + "config.toml"
	if lines := wrapText(path, 40); len(lines) != 1 || lines[0] != path {
		t.Errorf("split a single word into %d lines", len(lines))
	}
}

// The glyph is what makes the column scannable; the word is what survives a
// pipe into a log.  Both, and neither instead of the other.
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

// A terminal that was not told to expect UTF-8 gets the word alone rather than
// a replacement character against every finding.
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

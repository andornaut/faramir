package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/doctor"
	"github.com/andornaut/faramir/internal/termui"
)

// doctor's detail carries a path from the config and an error string from the
// host, and a filename may hold anything the filesystem accepts. A terminal
// obeys what it is sent, so a carriage return in a detail would overwrite the
// status beside it, on the one command an operator runs to find out whether the
// install is sound.
func TestADoctorDetailCannotReachTheTerminal(t *testing.T) {
	report := doctor.Report{Findings: []doctor.Finding{
		{Name: "config", Status: doctor.StatusFailed, Detail: "cannot read /etc/f\rSAFE/x"},
		{Name: "secrets", Status: doctor.StatusWarn, Detail: "a file named boom\x1bc will not load"},
		{Name: "store", Status: doctor.StatusWarn, Detail: "a title\x1b]0;pwned\a here"},
	}}
	var out bytes.Buffer
	printDiagnosis(&out, termui.Palette{}, report)
	if i := strings.IndexFunc(out.String(), func(r rune) bool {
		return (r < 0x20 && r != '\n' && r != '\t') || (r >= 0x7f && r <= 0x9f)
	}); i >= 0 {
		t.Errorf("a control character reached the terminal at %d: %q", i, out.String())
	}
}

// And an ordinary detail keeps its words. Compared with the wrapping taken back
// out: a detail longer than the terminal is laid out across lines, which is the
// layout doing its job rather than the escaping changing the text.
func TestAnOrdinaryDoctorDetailKeepsItsWords(t *testing.T) {
	const detail = "/etc/faramir/config.toml is what this install renders: 12 rule(s)"
	var out bytes.Buffer
	printDiagnosis(&out, termui.Palette{}, doctor.Report{Findings: []doctor.Finding{
		{Name: "deny patterns", Status: doctor.StatusOK, Detail: detail},
	}})
	got := strings.Join(strings.Fields(out.String()), " ")
	if !strings.Contains(got, strings.Join(strings.Fields(detail), " ")) {
		t.Errorf("an ordinary detail was changed: %q", out.String())
	}
}

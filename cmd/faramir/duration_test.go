package main

import (
	"strings"
	"testing"
)

// Both spellings, because both are typed: a bare number is what these flags
// have always taken, and a duration is what a caller writes without thinking
// about the unit. The refusals are asserted for what they name, a message that
// says only "invalid syntax" being the friction this replaced.
func TestADurationFlagTakesBothSpellings(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
		says  string
	}{
		{value: "", want: 0},
		{value: "300", want: 300},
		{value: "0", want: 0},
		{value: "90s", want: 90},
		{value: "5m", want: 300},
		{value: "1h30m", want: 5400},
		{value: "1500ms", says: "whole seconds"},
		{value: "-5", says: "must not be negative"},
		{value: "-5m", says: "must not be negative"},
		{value: "nonsense", says: "takes a duration"},
		{value: "5 m", says: "takes a duration"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got, err := durationSeconds("--timeout", tc.value)
			if tc.says != "" {
				if err == nil {
					t.Fatalf("durationSeconds(%q) = %d, want a refusal naming %q",
						tc.value, got, tc.says)
				}
				if !strings.Contains(err.Error(), tc.says) {
					t.Errorf("refusal is %q, want it to name %q", err, tc.says)
				}
				if !strings.Contains(err.Error(), "--timeout") {
					t.Errorf("refusal is %q, and names no flag, so a caller reading it "+
						"does not know which one to retype", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("durationSeconds(%q): %v", tc.value, err)
			}
			if got != tc.want {
				t.Errorf("durationSeconds(%q) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}

// A default is stored in seconds and printed beside a flag that takes a
// duration, which is where a caller learns the spelling.
func TestADefaultIsShownAsADuration(t *testing.T) {
	if got := asDuration(600); got != "10m0s" {
		t.Errorf("asDuration(600) = %q, want 10m0s", got)
	}
}

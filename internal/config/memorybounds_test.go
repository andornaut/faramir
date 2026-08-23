package config

import (
	"strings"
	"testing"
)

// The two memory settings answer different questions and are sized against
// different things, so each has to be validated on its own terms: a percentage
// of the host for the cgroup total, a size for one process.
func TestTheMemoryBoundsAreHeldToTheirRanges(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"a percentage below the floor", "max_memory_percent = 5\n",
			"max_memory_percent must be between 10 and 100"},
		{"a percentage above the whole machine", "max_memory_percent = 101\n",
			"max_memory_percent must be between 10 and 100"},
		{"a per-process bound too small to start a command",
			"max_process_memory_mb = 64\n",
			"max_process_memory_mb must be between 256 and 1048576"},
		{"a per-process bound past any host",
			"max_process_memory_mb = 2097152\n",
			"max_process_memory_mb must be between 256 and 1048576"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, minimal+tc.body)
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// The defaults are the ones the units are rendered from, so a change to either
// moves what every install writes.
func TestTheMemoryDefaultsAreTheOnesTheUnitsCarry(t *testing.T) {
	command := DefaultCommand()
	if command.MaxMemoryPercent != 25 {
		t.Errorf("max_memory_percent default = %d, want 25", command.MaxMemoryPercent)
	}
	// Three times the largest brokered process measured on the fleet this was
	// sized against, and a twentieth of the runaway it exists to refuse.
	if command.MaxProcessMemoryMB != 4096 {
		t.Errorf("max_process_memory_mb default = %d, want 4096", command.MaxProcessMemoryMB)
	}
}

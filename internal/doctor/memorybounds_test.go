package doctor

import (
	"strings"
	"testing"
)

// The two limits are sized against different things, so nothing stops a
// per-process bound being set above the cgroup total. Where that happens the
// per-process bound is unreachable and a runaway meets the OOM killer, which is
// the outcome it was chosen over.
func TestDoctorSaysWhenThePerProcessBoundIsOutOfReach(t *testing.T) {
	for _, tc := range []struct {
		name              string
		perProcess, total int64
		want              Status
		says              string
	}{
		{"a per-process bound under the total", 1 << 30, 4 << 30, StatusOK, "one brokered process may allocate"},
		{"the two equal", 4 << 30, 4 << 30, StatusWarn, "out of reach"},
		{"a per-process bound above the total", 4 << 30, 1 << 30, StatusWarn, "out of reach"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := &Report{}
			reportMemoryBounds(report, tc.perProcess, true, tc.total, true)
			found := findingFor(t, *report, "memory bounds")
			if found.Status != tc.want {
				t.Errorf("status = %v, want %v: %s", found.Status, tc.want, found.Detail)
			}
			if !strings.Contains(found.Detail, tc.says) {
				t.Errorf("detail = %q, want it to say %q", found.Detail, tc.says)
			}
		})
	}
}

// A host whose unit names neither is bounded by the machine, which is worth
// saying rather than passing silently.
func TestDoctorSaysWhenNeitherBoundIsSet(t *testing.T) {
	report := &Report{}
	reportMemoryBounds(report, 0, false, 0, false)
	found := findingFor(t, *report, "memory bounds")
	if found.Status != StatusWarn {
		t.Errorf("status = %v, want a warning: %s", found.Status, found.Detail)
	}
	if !strings.Contains(found.Detail, "bounded by") {
		t.Errorf("detail = %q, want it to say the machine is the only bound", found.Detail)
	}
}

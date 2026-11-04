package doctor

import (
	"errors"
	"fmt"
	"strings"

	"github.com/andornaut/faramir/internal/runcmd"
)

// agentUnknown is the fix for every check skipped for want of the agent
// account's name.
const agentUnknown = "run doctor through sudo (SUDO_USER names the agent " +
	"account), or record it with `sudo faramir init --agent-user`"

// childCause is a failed child's own words, one detail line per line runcmd
// kept, without the command line runcmd puts in front of them. A child that
// wrote nothing is its exit status alone, and an error that did not come from
// runcmd is returned whole.
func childCause(err error) string {
	failed, ok := errors.AsType[*runcmd.Error](err)
	if !ok {
		return err.Error()
	}
	lines := make([]string, 0, len(failed.Lines))
	for _, line := range failed.Lines {
		lines = append(lines, strings.TrimSpace(line))
	}
	return strings.Join(lines, "\n")
}

// Status is a finding's verdict.
//
// Warn means the question could not be put, for want of root, runuser, systemd
// or a broker holding values; the install may be perfect. A check that can
// reach its subject and cannot establish it fails instead of guessing.
//
// N/a means the subject belongs to an arrangement this host was not installed
// with. It is reported rather than left out, and is not counted in NotAsked:
// re-running as root would not answer it.
type Status string

const (
	StatusOK     Status = "ok"
	StatusNA     Status = "n/a"
	StatusWarn   Status = "warn"
	StatusFailed Status = "failed"
)

// Finding is one check.
type Finding struct {
	Name   string `json:"check"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Report is the whole examination; Failed is the exit code a caller reads.
//
// NotAsked counts the checks that could not be put. A caller has to report it
// alongside the findings: one warn line can stand for a dozen unasked
// questions.
type Report struct {
	Failed   bool      `json:"failed"`
	NotAsked int       `json:"not_asked"`
	Findings []Finding `json:"findings"`
}

func (d *Report) addf(name string, status Status, format string, args ...any) {
	d.Findings = append(d.Findings, Finding{
		Name: name, Status: status, Detail: fmt.Sprintf(format, args...),
	})
	if status == StatusFailed {
		d.Failed = true
	}
}

// unaskedf records a check that could not be put: the warn line a reader sees
// and the count under the totals, which have to move together. count is what
// the one line stands for, more than one wherever a bail-out skips a list. A
// warn added through addf is the other kind, something this host has that
// re-running as root would not change.
func (d *Report) unaskedf(name string, count int, format string, args ...any) {
	d.NotAsked += count
	d.addf(name, StatusWarn, format, args...)
}

// merge appends another report's findings, carrying its verdict and its unasked
// count with them.
func (d *Report) merge(other Report) {
	d.Findings = append(d.Findings, other.Findings...)
	d.Failed = d.Failed || other.Failed
	d.NotAsked += other.NotAsked
}

// abandoned marks the rest of an examination that stopped before it began: one
// line under the totals, so a report holding a single failure cannot read as a
// host where everything else passed.
//
// The count is len(checks), which is what an abandoned run did not get to. Read
// off the list rather than kept as a constant beside it: a constant is a second
// place to change when a check is added, and nothing fails when it is not.
func abandoned(report *Report, why string) {
	report.unaskedf("examination", len(checks), "every other check not run: %s", why)
}

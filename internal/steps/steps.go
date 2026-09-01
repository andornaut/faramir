// Package steps is the recording a provisioning command keeps: one line per
// step, whether it changed anything, and the warnings that are not failures.
//
// Shared by internal/install, which provisions a host, and internal/enrol,
// which enrols a tree. Written once rather than once per command: the two run
// some of the same steps, doctor reports on the same concerns, and a name or a
// log line the two spelled differently would read as two hosts.
//
// It decides nothing and writes nothing. What a step does is the caller's; this
// is only what the caller says it did.
package steps

import "fmt"

// Step is one unit of work and whether it changed anything, so a configuration
// manager reads Changed rather than stat-ing the host.
type Step struct {
	Name    string `json:"step"`
	Changed bool   `json:"changed"`
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Named is one step and what to call it when a run stops there.
type Named struct {
	Name string
	Run  func() error
}

// Report is what every command's report carries, embedded so the recording is
// written once. Embedded anonymously, which is what keeps its fields at the top
// level of the document each command serialises to.
type Report struct {
	Changed bool   `json:"changed"`
	Steps   []Step `json:"steps"`
	// Warnings are the things that install cleanly and then do not work. Not
	// failures, each having a legitimate shape.
	Warnings []string `json:"warnings,omitempty"`
	// log receives one line per step. Unexported, so it is no part of the
	// document either report serialises to.
	log func(string)
}

// LogTo sends one line per step to fn. A setter rather than a field, the log
// being no part of what a report serialises to.
func (r *Report) LogTo(fn func(string)) { r.log = fn }

// The names a step reports itself under. Several flows run the same steps, and
// doctor reports on the same concerns, so each is spelled once.
const (
	LabelResolveIDs    = "resolveIDs"
	LabelPreconditions = "preconditions"
	LabelAgentConfig   = "agent config"
	LabelEnrolledTrees = "enrolled trees"
	LabelConfig        = "config"
)

// Record records one unit of work and its outcome.
func (r *Report) Record(name string, changed bool, detail string) {
	r.Steps = append(r.Steps, Step{Name: name, Changed: changed, Detail: detail})
	if changed {
		r.Changed = true
	}
	if r.log == nil {
		return
	}
	mark := "ok"
	if changed {
		mark = "changed"
	}
	line := fmt.Sprintf("%-9s %s", mark, name)
	if detail != "" {
		line += ": " + detail
	}
	r.log(line)
}

// Skip records a step that could not be evaluated. Only under DryRun.
func (r *Report) Skip(name, why string) {
	r.Steps = append(r.Steps, Step{Name: name, Skipped: true, Detail: why})
	if r.log != nil {
		r.log(fmt.Sprintf("%-9s %s: %s", "skipped", name, why))
	}
}

// Warnf records something that installs cleanly and then does not work.
func (r *Report) Warnf(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// DetailWithCount names a path and how much of it a step had to change, which
// is what separates a run that asserted a tree from one that rewrote it.
func DetailWithCount(path string, changed int) string {
	if changed == 0 {
		return path
	}
	return fmt.Sprintf("%s (%d path(s) regrouped or rechmodded)", path, changed)
}

package install

import (
	"os"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostsudo"
)

// writeSudoPamBlock puts the branch into every shared stack, which is what
// selects faramir's PAM service on a host whose sudo is sudo-rs.
//
// After the service file it names: a branch pointing at a service that is not
// there sends the executor to /etc/pam.d/other, which asks for a password
// nothing supplies.
func (r *runner) writeSudoPamBlock() (bool, error) {
	block, err := agentcfg.Render("etc/pam.d-sudo.tmpl", r.layout)
	if err != nil {
		return false, err
	}
	changed, landed := false, 0
	for _, path := range r.layout.SudoPamFiles() {
		if !hostfs.Exists(path) {
			continue
		}
		landed++
		r.warnForeignAuthModule(path)
		wrote, err := hostsudo.SpliceBlock(r.fs, path, block)
		if err != nil {
			return false, err
		}
		changed = changed || wrote
	}
	// Nowhere to put it. The grant is written either way, so this is the
	// difference between a host that escalates and one whose every sudo falls to
	// /etc/pam.d/other -- said here rather than left for the broker's own check,
	// which reports it in a sentence about the broker.
	if landed == 0 {
		r.warnf("this host's sudo is sudo-rs, which reaches the service named `sudo` and nothing a "+
			"caller may name, and neither %s exists to carry the stack that asks the broker: "+
			"every escalation falls to %s/other. Install sudo, then re-run this install",
			strings.Join(r.layout.SudoPamFiles(), " nor "), hostlayout.PamDir)
	}
	return changed, nil
}

// warnForeignAuthModule reports a stack that already authenticates with a module
// of somebody else's, which on these two files is usually a second factor.
//
// The block goes above it, and that is the right way round: for every other
// account the branch falls through and the module still runs, and for the
// executor the broker is the second factor already -- a human is being asked. It
// is still not faramir's call to make quietly. An operator who put a factor on
// this host's sudo should hear that one account now reaches root without it,
// and that two things are editing a file neither owns.
func (r *runner) warnForeignAuthModule(path string) {
	current, err := os.ReadFile(path)
	if err != nil {
		return
	}
	module := hostsudo.ForeignAuthModule(hostsudo.WithoutBlock(current))
	if module == "" {
		return
	}
	r.warnf("%s authenticates with a module of its own (%q) and faramir's branch goes above it, "+
		"so %s reaches root without meeting it. Every other account still does. Review this "+
		"if that module is a second factor", path, module, r.layout.ExecUser)
}

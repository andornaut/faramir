package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostsudo"
	"github.com/andornaut/faramir/internal/hostsudotest"
	"github.com/andornaut/faramir/internal/layouttest"
)

// sudoRsArrangement is a granting host whose sudo is sudo-rs: faramir's service
// reads the environment file with pam_env, and the branch that selects it is in
// both shared stacks.
func sudoRsArrangement(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := layouttest.SudoStacks(t)
	hostsudotest.PinSudo(t, true)

	// The block is the stack on a sudo-rs host, so the layout it renders from and
	// the config doctor reads have to name the same helper and the same
	// environment file. Both follow LibexecDir, which points at this directory.
	layout := layouttest.Layout()
	layout.LibexecDir = dir
	layout.SudoRs = true
	cfg := &config.Config{}
	cfg.Sudo.ExecUser = layout.ExecUser
	cfg.Sudo.PamService = hostlayout.PamServiceName
	cfg.Sudo.Helper = layout.PamHelper()
	if err := os.WriteFile(layout.SudoEnvFile(),
		[]byte("FARAMIR_OPERATOR=op\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Named on the block's requisite line, so the arrangement is not whole
	// without it.
	if err := os.WriteFile(cfg.Sudo.Helper, []byte("#!/bin/sh\nexit 0\n"),
		0o700); err != nil {
		t.Fatal(err)
	}
	// The block spliced in the way the install writes it.
	block, err := agentcfg.Render("etc/pam.d-sudo.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range layout.SudoPamFiles() {
		if _, err := hostsudo.SpliceBlock(hostfs.FS{}, path, block); err != nil {
			t.Fatal(err)
		}
	}
	return cfg, dir
}

// The whole sudo-rs arrangement passes, and the branch going missing fails.
// /etc/pam.d/sudo is a dpkg conffile: an upgrade that installs the maintainer's
// version drops the block without saying so, and every escalation fails after
// it with nothing naming the cause.
func TestTheSudoRsArrangementFailsWhenTheBranchIsGone(t *testing.T) {
	cfg, dir := sudoRsArrangement(t)
	opts := Options{ExecUser: "ex", AgentUser: "op"}

	var whole Report
	diagnoseSudoArrangement(&whole, opts, cfg)
	if got := only(t, whole); got.Status != StatusOK {
		t.Fatalf("status %q, want %q with the whole arrangement in place: %s",
			got.Status, StatusOK, got.Detail)
	}

	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(layouttest.StockSudoStack), 0o644); err != nil {
		t.Fatal(err)
	}
	var without Report
	diagnoseSudoArrangement(&without, opts, cfg)
	finding := only(t, without)
	if finding.Status != StatusFailed {
		t.Errorf("status %q, want %q with the branch gone: %s",
			finding.Status, StatusFailed, finding.Detail)
	}
	if !strings.Contains(finding.Detail, filepath.Join(dir, "sudo")) {
		t.Errorf("the failure does not name the stack it is about: %s", finding.Detail)
	}
}

// A host whose `sudo` alternatives group was switched after an install is
// reported, and the two directions do not have the same answer.
//
// Toward sudo-rs the grant is broken: sudo-rs reaches the service called `sudo`
// for everybody and refuses the pam_service settings the original arrangement
// carries, so nothing can be approved.
//
// Toward the original it still works. The sudo-rs arrangement writes no
// pam_service line, so the original sudo uses its own default service, which is
// the file faramir's block is in. Reporting that as a failure said every
// escalation fails on a host where each one succeeds, and this is the line an
// operator reads to decide whether escalation works.
func TestSwitchingTheSudoAlternativeIsReported(t *testing.T) {
	t.Run("rendered for the original, host now sudo-rs", func(t *testing.T) {
		cfg, _ := sudoArrangement(t)
		hostsudotest.PinSudo(t, true)
		var report Report
		diagnoseSudoArrangement(&report, Options{ExecUser: "ex", AgentUser: "op"}, cfg)
		finding := only(t, report)
		if finding.Status != StatusFailed {
			t.Fatalf("status %q, want %q: %s", finding.Status, StatusFailed, finding.Detail)
		}
		if !strings.Contains(finding.Detail, "sudo-rs") {
			t.Errorf("the failure does not name what the host now runs: %s", finding.Detail)
		}
	})
	t.Run("rendered for sudo-rs, host now the original", func(t *testing.T) {
		cfg, _ := sudoRsArrangement(t)
		hostsudotest.PinSudo(t, false)
		var report Report
		diagnoseSudoArrangement(&report, Options{ExecUser: "ex", AgentUser: "op"}, cfg)
		finding := only(t, report)
		if finding.Status != StatusWarn {
			t.Fatalf("status %q, want %q: %s", finding.Status, StatusWarn, finding.Detail)
		}
		// The verdict has to say the grant works, or an operator reads it as the
		// other direction and goes looking for a break that is not there.
		if !strings.Contains(finding.Detail, "escalation works") {
			t.Errorf("the warning does not say the grant still works: %s", finding.Detail)
		}
		if !strings.Contains(finding.Detail, "--allow-sudo") {
			t.Errorf("the warning does not say how to write the right arrangement: %s",
				finding.Detail)
		}
	})
}

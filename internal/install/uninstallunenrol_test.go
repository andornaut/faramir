package install

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/enrol"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostunit"
)

// uninstallEvents is uninstallOps that records what it was asked to do, in
// order, and removes nothing.
func uninstallEvents(events *[]string, failTree string) uninstallOps {
	return uninstallOps{
		remove:      func(path string) error { *events = append(*events, "remove "+path); return nil },
		removeAll:   func(path string) error { *events = append(*events, "remove "+path); return nil },
		removeBlock: func() error { return nil },
		unenrol: func(opts enrol.UnenrolOptions) (enrol.UnenrolReport, error) {
			*events = append(*events, "unenrol "+opts.Dir+" "+opts.AgentUser+" "+opts.ConfigDir)
			if opts.Dir == failTree {
				return enrol.UnenrolReport{}, errors.New("half-marked section")
			}
			report := enrol.UnenrolReport{Dir: opts.Dir}
			report.Warnf("kept sharing on %s", opts.Dir)
			return report, nil
		},
		unenrolHome: func(account string) (enrol.UnenrolReport, error) {
			*events = append(*events, "home "+account)
			return enrol.UnenrolReport{Dir: "/home/" + account}, nil
		},
	}
}

func notRunning(t *testing.T) {
	t.Helper()
	previous := hostunit.Running
	hostunit.Running = func() bool { return false }
	t.Cleanup(func() { hostunit.Running = previous })
}

// Every recorded tree and the agent account's home are unenrolled before the
// binary their hooks and plugins exec is removed, and a tree that is missing or
// cannot be unenrolled is a warning naming it rather than a failed uninstall.
func TestUninstallUnenrolsEveryTreeBeforeRemovingTheBinary(t *testing.T) {
	notRunning(t)
	configDir := t.TempDir()
	if err := os.WriteFile(config.FileIn(configDir), []byte("[server]\nagent_user = \"op\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleaned, failing, missing := t.TempDir(), t.TempDir(), filepath.Join(t.TempDir(), "gone")
	for _, dir := range []string{cleaned, missing, failing} {
		if err := agentcfg.RecordEnrolment(configDir,
			agentcfg.EnrolledTree{Dir: dir, AgentUser: "op", Agents: []string{"claude"}}); err != nil {
			t.Fatal(err)
		}
	}
	var events []string
	report, err := uninstall(uninstallEvents(&events, failing), configDir)
	if err != nil {
		t.Fatalf("a tree that could not be unenrolled failed the uninstall: %v", err)
	}
	binary := slices.Index(events, "remove "+filepath.Join(hostlayout.DefaultBinDir, "faramir"))
	if binary < 0 {
		t.Fatalf("the binary was not removed: %q", events)
	}
	for _, want := range []string{
		"unenrol " + cleaned + " op " + configDir,
		"unenrol " + failing + " op " + configDir,
		"home op",
	} {
		at := slices.Index(events, want)
		switch {
		case at < 0:
			t.Errorf("not asked: %q in %q", want, events)
		case at > binary:
			t.Errorf("%q ran after the binary was removed", want)
		}
	}
	if slices.ContainsFunc(events, func(event string) bool { return strings.HasPrefix(event, "unenrol "+missing) }) {
		t.Errorf("a missing tree was unenrolled, which forgets its record: %q", events)
	}
	if want := []string{cleaned, "/home/op (account-wide)"}; !slices.Equal(report.Unenrolled, want) {
		t.Errorf("unenrolled = %q, want %q", report.Unenrolled, want)
	}
	warnings := strings.Join(report.Warnings, "\n")
	for _, want := range []string{
		"enrolled tree " + missing + " not unenrolled: no directory there",
		"enrolled tree " + failing + " not unenrolled: half-marked section",
		"kept sharing on " + cleaned,
	} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings omit %q:\n%s", want, warnings)
		}
	}
}

// An install whose config names no agent account still unenrols its trees, and
// says the account-wide half was not cleaned.
func TestUninstallWithoutAnAgentAccountWarns(t *testing.T) {
	notRunning(t)
	configDir := t.TempDir()
	var events []string
	report, err := uninstall(uninstallEvents(&events, ""), configDir)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(events, func(event string) bool { return strings.HasPrefix(event, "home ") }) {
		t.Errorf("a home was cleaned with no agent account: %q", events)
	}
	if !slices.ContainsFunc(report.Warnings, func(warning string) bool {
		return strings.HasPrefix(warning, "account-wide agent configuration not removed: no agent account in ")
	}) {
		t.Errorf("warnings = %q", report.Warnings)
	}
}

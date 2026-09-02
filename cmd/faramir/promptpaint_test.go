package main

// Where colour is and is not offered. What the escalation screens paint is
// asserted in internal/sudoprompt; this is about which commands take --color
// and that a JSON listing never carries an escape.

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/termuitest"
	"github.com/andornaut/faramir/internal/testio"
)

// --json is for a caller parsing stdout, and --color is about a human reading
// it: the two never meet, whatever the flags say.
func TestTheJSONListingIsNeverPainted(t *testing.T) {
	socket := escalationsSocket(t, []escalation.Question{{
		ID: "9f2a1c", Cmd: "ansible-playbook site.yml", ExpiresInSec: 118,
	}})
	out, _ := testio.CaptureStdout(t, func() int { return listEscalations(socket, true, termuitest.Always(t)) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("the JSON listing carries an escape:\n%q", out)
	}
}

// One flag, spelled once: the commands that paint take the same --color, and
// the ones that do not take none. A persistent flag on the root command would
// have advertised it on `run`, where it decides nothing.
func TestOnlyThePaintingCommandsTakeColor(t *testing.T) {
	const usage = "colourise: auto, always or never"
	for _, tc := range []struct {
		name    string
		command func() *cobra.Command
	}{
		{"logs", newLogsCmd},
		{"doctor", newDoctorCmd},
		{"sudo ls", newSudoListCmd},
		{"sudo watch", newSudoWatchCmd},
		{"sudo reject", newRejectCmd},
	} {
		flag := tc.command().Flags().Lookup("color")
		if flag == nil {
			t.Errorf("faramir %s prints a report and takes no --color", tc.name)
			continue
		}
		if flag.DefValue != "auto" || flag.Usage != usage {
			t.Errorf("faramir %s spells --color differently: %q, %q",
				tc.name, flag.DefValue, flag.Usage)
		}
	}
	for _, tc := range []struct {
		name    string
		command func() *cobra.Command
	}{
		{"run", newRunCmd},
		{"sudo approve", newApproveCmd},
	} {
		if tc.command().Flags().Lookup("color") != nil {
			t.Errorf("faramir %s prints no report and takes --color anyway", tc.name)
		}
	}
}

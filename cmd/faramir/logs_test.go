package main

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/auditview"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/testio"
)

// A log-id names one record that is already written, so there is nothing to
// wait for. Blocked before the root check and before the config is read, so an
// operator who typed both is told which is wrong rather than told to use sudo
// and then told this.
func TestLogsRefusesAWatchWithALogID(t *testing.T) {
	f := logsFlags{when: "never", watch: true, count: 20}
	said, code := testio.CaptureStderr(t, func() int { return runLogs(f, []string{"a"}) })
	if code != 2 {
		t.Errorf("faramir logs --watch w5vq7dbg000002 = %d, want 2 (usage)", code)
	}
	// Which of the two to drop: a refusal that only says the pair is wrong
	// leaves the caller to guess, and the guess costs another run as root.
	if !strings.Contains(said, "takes no log-id") {
		t.Errorf("the refusal does not say which half is wrong: %q", said)
	}
}

// An unknown --color is refused before anything is read, so it is a usage error
// rather than the exit 1 that says the log could not be reached. Decided in
// runLogs and not only in newPalette: the status the shell sees is what tells a
// script it was invoked wrongly.
func TestLogsRefusesAnUnknownColour(t *testing.T) {
	f := logsFlags{when: "pink", count: 20}
	said, code := testio.CaptureStderr(t, func() int { return runLogs(f, nil) })
	if code != 2 {
		t.Errorf("faramir logs --color pink = %d, want 2 (usage)", code)
	}
	if !strings.Contains(said, "pink") {
		t.Errorf("the refusal does not name what was passed: %q", said)
	}
}

// opWidth is a number somebody has to keep true, and the case above proves only
// that one name fits: pad appends a space to anything already at the width, so
// an op as wide as its column shifts every column after it. logs.go names the
// ops it renders rather than importing them, and this is where the two meet.
func TestEveryOpFitsTheColumn(t *testing.T) {
	ops := append([]string{auditview.OpRunStarted, opAdd, auditview.OpEdit, opRemove, auditview.OpReseal, opReader},
		protocol.Ops...)
	for _, op := range ops {
		t.Run(op, func(t *testing.T) {
			if len(op) >= auditview.OpWidth {
				t.Errorf("op %q is %d wide and opWidth is %d, so it leaves no separating "+
					"space; raise opWidth past the longest op", op, len(op), auditview.OpWidth)
			}
		})
	}
}

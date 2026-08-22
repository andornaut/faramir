package main

// Colour on the escalation surfaces. The question is the one screen where a
// reader has to tell faramir's words from the agent's, so what is painted there
// is chrome and what is left plain is the caller's; the endings a watcher
// prints are read beside `faramir logs`, so they carry its colours.

import (
	"bufio"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/escalation"
)

// The colours the palette emits, named here so the assertions below read as
// what an operator sees rather than as numbers.
const (
	sgrReset = "\x1b[0m"
	sgrBold  = "\x1b[1m"
	sgrDim   = "\x1b[2m"
	sgrRed   = "\x1b[31m"
	sgrGreen = "\x1b[32m"
	sgrCyan  = "\x1b[36m"
)

func askedQuestion() escalation.Question {
	return escalation.Question{
		ID: "9f2a1c", LogID: "w5vq7dbf000119",
		Cmd: "ansible-playbook site.yml", Cwd: "/srv/ansible",
		Caller: "you (uid 1000)", Host: "controller",
		ExpiresInSec: 118,
		Received:     "2026-08-20T20:21:44-04:00",
	}
}

// The label is faramir's word and the value is the agent's, and only the first
// is painted. Not because a painted value could inject anything -- the broker
// renders the caller's strings before they are sent -- but because the field
// boundary is what a reader judges by, and a highlight that straddles it is
// what an attacker would want. Asserted as the value sitting bare between the
// label's reset and the newline, which is the shape no span reaches across.
func TestTheQuestionPaintsItsLabelsAndNotItsValues(t *testing.T) {
	question := askedQuestion()
	out, _ := captureStdout(t, func() int { printQuestion(question, always(t)); return 0 })
	if !strings.Contains(out, sgrCyan) {
		t.Fatalf("colour is on and no label was painted:\n%q", out)
	}
	for _, value := range []string{question.Cmd, question.Cwd, question.Caller, question.Host} {
		if !strings.Contains(out, sgrReset+value+"\n") {
			t.Errorf("%q is not printed bare after its label:\n%q", value, out)
		}
	}
}

// The two ids are dimmed, as the log id is dimmed in a `faramir logs` row: they
// are how this question is looked up afterwards, not what it is judged on.
func TestTheQuestionDimsTheIDsAndBoldsThePrompt(t *testing.T) {
	question := askedQuestion()
	out, _ := captureStdout(t, func() int { printQuestion(question, always(t)); return 0 })
	if !strings.Contains(out, sgrBold+escalation.PromptPrefix+sgrReset) {
		t.Errorf("the sentence being answered is not bold:\n%q", out)
	}
	for _, id := range []string{question.ID, question.LogID} {
		if !strings.Contains(out, sgrDim+id+sgrReset) {
			t.Errorf("%q is not dimmed:\n%q", id, out)
		}
	}
}

// --color=never is the whole of it: a question piped into a file or read by a
// terminal that was told not to is the same text it always was.
func TestTheQuestionCarriesNoEscapesWithColourOff(t *testing.T) {
	out, _ := captureStdout(t, func() int { printQuestion(askedQuestion(), plain(t)); return 0 })
	if strings.Contains(out, "\x1b") {
		t.Errorf("colour is off and an escape was printed anyway:\n%q", out)
	}
}

// The same green and red the log's outcome column uses, the same operator
// reading both: an exit status of 0 is the only clean ending there is.
func TestTheEndingsCarryTheSameColoursAsTheLog(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome escalation.Outcome
		want    string
	}{
		{"a clean exit", escalation.Outcome{LogID: "log-1", ExitCode: new(0), DurationSec: 1.2}, sgrGreen},
		{"a non-zero exit", escalation.Outcome{LogID: "log-2", ExitCode: new(2), DurationSec: 1.2}, sgrRed},
		{
			"a run the executor ended",
			escalation.Outcome{LogID: "log-3", ExitCode: new(2), DurationSec: 1.2, TimedOut: true},
			sgrRed,
		},
		{"a run with no exit status", escalation.Outcome{LogID: "log-4"}, sgrRed},
		{"a run the broker could not report", escalation.Outcome{LogID: "log-5", Error: "gone"}, sgrRed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := captureStdout(t, func() int { printOutcome(tc.outcome, always(t)); return 0 })
			if !strings.Contains(out, tc.want) {
				t.Errorf("the ending is not painted %q:\n%q", tc.want, out)
			}
			if !strings.Contains(out, sgrDim+tc.outcome.LogID+sgrReset) {
				t.Errorf("the log id is not dimmed:\n%q", out)
			}
		})
	}
}

// A clean ending is green and nothing else is, which is the whole of what a
// watcher left running all afternoon is scanned for.
func TestOnlyACleanEndingIsGreen(t *testing.T) {
	out, _ := captureStdout(t, func() int {
		printOutcome(escalation.Outcome{LogID: "log-2", ExitCode: new(2), DurationSec: 1.2}, always(t))
		return 0
	})
	if strings.Contains(out, sgrGreen) {
		t.Errorf("a failed run was painted as a clean one:\n%q", out)
	}
}

// The ask is the last thing on the screen before the cursor, and the cursor
// sits on a plain space rather than inside the highlight.
func TestTheAnswerPromptIsBold(t *testing.T) {
	original := answers
	t.Cleanup(func() { answers = original })
	answers = bufio.NewReader(strings.NewReader("y\n"))

	out, _ := captureStdout(t, func() int {
		readLines(always(t)).answer(time.Now().Add(time.Minute))
		return 0
	})
	if !strings.Contains(out, sgrBold+"approve? [y/n]"+sgrReset+" ") {
		t.Errorf("the ask is not bold, or the space landed inside the span:\n%q", out)
	}
}

// --json is for a caller parsing stdout, and --color is about a human reading
// it: the two never meet, whatever the flags say.
func TestTheJSONListingIsNeverPainted(t *testing.T) {
	socket := escalationsSocket(t, []escalation.Question{{
		ID: "9f2a1c", Cmd: "ansible-playbook site.yml", ExpiresInSec: 118,
	}})
	out, _ := captureStdout(t, func() int { return listEscalations(socket, true, always(t)) })
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
		{"sudo deny", newDenyCmd},
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

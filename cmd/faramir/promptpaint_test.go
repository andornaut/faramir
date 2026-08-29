package main

// Colour on the escalation surfaces. The question is the one screen where a
// reader has to tell faramir's words from the agent's, so what is painted there
// is chrome and what is left plain is the caller's; the endings a watcher
// prints are read beside `faramir logs`, so they carry its colours.

import (
	"bufio"
	"slices"
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
	if !strings.Contains(out, sgrBold+"Approve? [y/n]"+sgrReset+" ") {
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

// The order the question is read in, which is what a reader scanning a terminal
// relies on and nothing else pins. The command and what it resolved to come
// first and adjacent: the question a reader asks first is what is about to run,
// and it is answered by those two lines together. Where and who follow, being a
// different question, and the clock last.
func TestTheQuestionReadsInTheOrderItIsJudgedIn(t *testing.T) {
	question := askedQuestion()
	question.Program = "/srv/ansible/bin/ansible-playbook"
	out, _ := captureStdout(t, func() int { printQuestion(question, plain(t)); return 0 })

	printed := questionLabels(out)
	want := []string{"id", "log_id", "cmd", "program", "cwd", "caller", "host", "received"}
	if len(printed) < len(want) {
		t.Fatalf("printed %d labelled lines, want at least %d: %q", len(printed), len(want), out)
	}
	for i, label := range want {
		if printed[i] != label {
			t.Errorf("line %d is %q, want %q. The whole question reads:\n%s",
				i+1, printed[i], label, out)
		}
	}
}

// questionLabels is the label of each field the question printed, in order. The
// labels rather than the rendered text: a value is the caller's and may say
// anything, "cwd /srv/programs" among it, so a test reading the whole output
// decides on a word the agent chose.
func questionLabels(out string) []string {
	var labels []string
	for line := range strings.Lines(out) {
		// A field is indented; the sentence above them is not.
		if !strings.HasPrefix(line, "  ") {
			continue
		}
		if fields := strings.Fields(line); len(fields) > 0 {
			labels = append(labels, fields[0])
		}
	}
	return labels
}

// And the resolved program is dropped rather than left as a gap when the broker
// has nothing to say about it: the command is followed by the cwd, with nothing
// between the two.
func TestTheQuestionLeavesNoRoomForAProgramItWasNotGiven(t *testing.T) {
	question := askedQuestion()
	// A cwd that says "program" without a program row being printed, which is
	// what a test reading the rendered text rather than the labels would trip on.
	question.Cwd = "/srv/programs"
	out, _ := captureStdout(t, func() int { printQuestion(question, plain(t)); return 0 })
	labels := questionLabels(out)
	if slices.Contains(labels, "program") {
		t.Errorf("a program row was printed for a question carrying none:\n%s", out)
	}
	// Adjacency, not order: a field inserted between the two would pass a test
	// that only asked which came first.
	cmd := slices.Index(labels, "cmd")
	if cmd < 0 || cmd+1 >= len(labels) {
		t.Fatalf("no cmd row, or nothing after it: %v", labels)
	}
	if labels[cmd+1] != "cwd" {
		t.Errorf("cmd is followed by %q, want cwd with no row between:\n%s",
			labels[cmd+1], out)
	}
}

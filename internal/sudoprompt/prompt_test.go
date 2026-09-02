package sudoprompt

import (
	"bufio"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/termui"
	"github.com/andornaut/faramir/internal/testio"
)

// A sentence is an answer, not a closed stdin: a reader that treats anything
// past the first word as end of input exits the watch, leaving the question to
// expire unanswered.
func TestAWordyAnswerIsReadAsAnAnswer(t *testing.T) {
	original := answers
	t.Cleanup(func() { answers = original })
	answers = bufio.NewReader(strings.NewReader("y please\n\ny\n"))
	terminal := ReadLines(termui.Palette{})
	for _, want := range []bool{
		false, // "y please" is not y, and is still an answer
		true,  // the blank line is asked again, and the y after it read
	} {
		line, state := terminal.Answer(time.Now().Add(time.Minute))
		if state != Answered {
			t.Fatalf("the wait ended in state %v, want an answer", state)
		}
		if termui.Approves(line) != want {
			t.Errorf("termui.Approves(%q) = %v, want %v", line, termui.Approves(line), want)
		}
	}
	// And only a closed stdin ends the watch.
	if _, state := terminal.Answer(time.Now().Add(time.Minute)); state != StdinClosed {
		t.Errorf("the wait ended in state %v past the end of its input, want StdinClosed", state)
	}
}

// The line is returned as it was read, so a refusal can quote it. An answer
// nobody typed refuses a question exactly as one they did, and a refusal that
// does not say what it read cannot be told from the operator's own no.
func TestReadAnswerReturnsWhatItRead(t *testing.T) {
	original := answers
	t.Cleanup(func() { answers = original })
	answers = bufio.NewReader(strings.NewReader("\x1b[?62;c\n"))
	line, state := ReadLines(termui.Palette{}).Answer(time.Now().Add(time.Minute))
	if state != Answered {
		t.Fatalf("the wait ended in state %v, want an answer", state)
	}
	if line != "\x1b[?62;c\n" {
		t.Errorf("readAnswer = %q, want the line as it arrived", line)
	}
	if termui.Approves(line) {
		t.Error("a terminal's own reply approved an escalation")
	}
}

// A re-ask does not throw away what was typed against the prompt it is
// re-asking. The flush is for input that predates the question; after the first
// prompt there is none, and flushing again eats the answer to a blank line typed
// ahead of it.
func TestARetryKeepsWhatWasTypedAfterThePrompt(t *testing.T) {
	original := answers
	t.Cleanup(func() { answers = original })
	// One burst: a stray newline, then the answer behind it.
	answers = bufio.NewReader(strings.NewReader("\ny\n"))
	line, state := ReadLines(termui.Palette{}).Answer(time.Now().Add(time.Minute))
	if state != Answered || !termui.Approves(line) {
		t.Errorf("the wait gave (%q, %v), want the y behind the blank line", line, state)
	}
}

// The wait rides the received line, and only where it says something. A
// watcher already running is answered the moment a question is filed, so zero is
// the ordinary reading and its absence says as much. It is the other case the
// number is for: nobody was here yet. Past tense, because the line is printed
// once and the number is frozen at what it was then.
func TestTheWaitedCountIsPrintedOnlyWhenItSaysSomething(t *testing.T) {
	question := escalation.Question{
		ID: "9f2a1c", Prompt: "faramir: Approve this command to run as root? `true`",
		Cmd: "true", ExpiresInSec: 120,
		Received: "2026-08-20T20:21:44-04:00",
	}
	fresh, _ := testio.CaptureStdout(t, func() int { PrintQuestion(question, termui.Palette{}); return 0 })
	if strings.Contains(fresh, "waited") {
		t.Errorf("a question nobody was late for reports a wait:\n%s", fresh)
	}
	// The zone token is not pinned: Go resolves the offset against wherever this
	// runs, so it is EDT on the machine that wrote this and UTC in CI. What is
	// asserted is the moment and the clock beside it.
	if !strings.Contains(fresh, "received 2026-08-20 20:21:44 ") ||
		!strings.Contains(fresh, "(expires 120s)") {
		t.Errorf("the moment it was asked, and the clock the answer is typed "+
			"against, are not both there:\n%s", fresh)
	}

	question.WaitingSec, question.ExpiresInSec = 40, 80
	late, _ := testio.CaptureStdout(t, func() int { PrintQuestion(question, termui.Palette{}); return 0 })
	if !strings.Contains(late, "received 2026-08-20 20:21:44 ") ||
		!strings.Contains(late, "(expires 80s, waited 40s)") {
		t.Errorf("a question that sat for 40s does not say so on the received line:\n%s", late)
	}
	// One line, not two: the wait qualifies the clock rather than standing beside it.
	if strings.Contains(late, "\n  waited") {
		t.Errorf("the wait is still a line of its own:\n%s", late)
	}
}

// The timestamp is the broker's, in the zone it recorded it in, and a question
// carrying none or carrying nonsense still prints the rest: the line an operator
// answers against is the expiry, and dropping it over an unparseable stamp would
// take that with it.
func TestTheReceivedStampSurvivesABrokerThatSaidSomethingOdd(t *testing.T) {
	for stamp, want := range map[string]string{
		// An offset no machine running this is in, so the zone token is the offset
		// itself wherever the test runs. Go resolves an offset that matches the
		// local zone to its name instead, which is what makes this read like the
		// day heading `logs` prints, and what makes pinning a name here flaky.
		"2026-08-20T20:21:44+05:45": "received 2026-08-20 20:21:44 +0545 (expires 120s)",
		"":                          "received (unknown) (expires 120s)",
		"not-a-time":                "received not-a-time (expires 120s)",
	} {
		question := escalation.Question{ID: "9f2a1c", Cmd: "true", ExpiresInSec: 120, Received: stamp}
		out, _ := testio.CaptureStdout(t, func() int { PrintQuestion(question, termui.Palette{}); return 0 })
		if !strings.Contains(out, want) {
			t.Errorf("Received=%q rendered without %q:\n%s", stamp, want, out)
		}
	}
}

// A question nobody answers ends the wait on its own clock, so the terminal
// stops asking about one the broker has already refused and the loop goes back
// to the poll. Without it the read holds the loop until somebody types, and a
// question raised in the meantime is not shown.
func TestTheWaitEndsWhenTheQuestionExpires(t *testing.T) {
	original := answers
	t.Cleanup(func() { answers = original })
	// A reader with nothing in it and no end, which is a terminal nobody types at.
	answers = bufio.NewReader(blockingReader{make(chan struct{})})

	start := time.Now()
	line, state := ReadLines(termui.Palette{}).Answer(time.Now().Add(150 * time.Millisecond))
	if state != Expired {
		t.Errorf("the wait ended in state %v with %q, want expired", state, line)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("the wait took %v, so it was not the question's clock that ended it", waited)
	}
}

// blockingReader never returns and never ends, which is what stdin is when the
// operator is not at the keyboard.
type blockingReader struct{ never chan struct{} }

func (r blockingReader) Read([]byte) (int, error) {
	<-r.never
	return 0, io.EOF
}

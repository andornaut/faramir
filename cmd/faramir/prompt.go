package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/auditview"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/termui"
)

// waitedIn is how much of the duration was the question rather than the
// command, where that is worth saying. The duration is wall time from fork to
// exit and the child sits inside sudo for the whole escalation, so a slowly
// answered run would otherwise read as a slow command. Said rather than
// subtracted: [command] max_timeout_sec is enforced against the same clock.
// ranFor is how long the command itself took, and what the wait and the total
// were where the command sat blocked on its own escalation.
//
// The run time leads because it is the number being asked for: DurationSec is
// wall clock from the moment the command registered, so a script that failed
// the instant it was approved and one that ran for a minute read the same until
// the wait is subtracted. The total stays because the exec timeout is enforced
// against it, and a command killed at timeout_sec is unexplainable without it.
func ranFor(outcome escalation.Outcome) string {
	if outcome.WaitedSec < 1 {
		return fmt.Sprintf("in %.1fs", outcome.DurationSec)
	}
	// The same precision throughout, or a wait of 40.6s beside a duration of
	// 41.0s reads as a command that took no time at all.
	return fmt.Sprintf("in %.1fs (%.1fs waiting to be approved, %.1fs total)",
		outcome.DurationSec-outcome.WaitedSec, outcome.WaitedSec, outcome.DurationSec)
}

// printOutcome says how the approved run ended, in one line naming the record
// rather than reproducing it: the log holds the command, the refs and the
// output. A run with no exit code is said to have ended without one, a zero
// there reading as a clean exit.
func printOutcome(outcome escalation.Outcome, paint termui.Palette) {
	// The same green and red `faramir logs` gives the outcome column, the same
	// operator reading both: a watcher left running all afternoon is scanned for
	// the endings that were not clean. The log id is dimmed as it is there, and
	// the ending itself carries the colour -- an exit status of 0 is the only
	// green there is, everything else being something that asked to be read.
	id := paint.Dim(outcome.LogID)
	switch {
	case outcome.Error != "":
		fmt.Printf("  %s %s\n", id, paint.Bad("failed: "+outcome.Error))
	case outcome.ExitCode == nil:
		fmt.Printf("  %s %s\n", id, paint.Bad("ended, no exit status"))
	case outcome.TimedOut:
		fmt.Printf("  %s %s\n", id, paint.Bad(fmt.Sprintf("exited %d %s, timed out",
			*outcome.ExitCode, ranFor(outcome))))
	default:
		ending := fmt.Sprintf("exited %d %s", *outcome.ExitCode, ranFor(outcome))
		if outcome.StatusUnknown {
			ending += ", exit status unknown"
		}
		if *outcome.ExitCode != 0 {
			fmt.Printf("  %s %s\n", id, paint.Bad(ending))
			break
		}
		fmt.Printf("  %s %s\n", id, paint.OK(ending))
	}
}

// warnIfTypeable says so when this terminal is one the coding agent could type
// into. The socket check makes the answer come from root; it cannot make root
// the one doing the typing.
//
//   - A multiplexer. tmux and screen keep a per-uid control socket, so any
//     process running as the operator can `tmux send-keys` into this pane. Same
//     uid is the whole requirement; no sharing has to be intended.
//   - A tty owned by somebody other than root. `sudo` leaves the terminal owned
//     by the account that invoked it, so a root process reads from a device that
//     account still owns. What that gives an attacker depends on the kernel and
//     on ptrace_scope, hence a warning rather than a claim.
//
// A real console, an ssh session from another machine, or a login as another
// account have neither problem.
func warnIfTypeable() {
	var reasons []string
	if os.Getenv("TMUX") != "" {
		reasons = append(reasons, "this is a tmux pane, and tmux takes `send-keys` "+
			"from any process running as the account that started it")
	}
	if os.Getenv("STY") != "" {
		reasons = append(reasons, "this is a screen window, and screen takes `stuff` "+
			"from any process running as the account that started it")
	}
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
			owner := strconv.FormatUint(uint64(stat.Uid), 10)
			if entry, err := user.LookupId(owner); err == nil {
				owner = entry.Username
			}
			reasons = append(reasons, "this terminal belongs to "+owner+" rather than "+
				"to root, so the answer is typed on a device that account owns")
		}
	}
	if len(reasons) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr, "\nWARNING: an escalation given here may not be yours.")
	for _, reason := range reasons {
		fmt.Fprintln(os.Stderr, "  - "+reason)
	}
	fmt.Fprint(os.Stderr, "The coding agent runs as that account. Watch from a console, an ssh session on "+
		"another machine, or another login: somewhere it cannot reach the keyboard.\n\n")
}

// answers reads the operator's terminal a line at a time. One reader for the
// life of the watcher: a fresh one per question would buffer past the newline
// and eat the answer to the next.
var answers = bufio.NewReader(os.Stdin)

// fromTerminal is answers as it starts out, compared against in readLines to
// set the terminal field discard reads: a test substitutes a reader of its own,
// whose scripted answers are read in order rather than discarded.
var fromTerminal = answers

// typed is the operator's terminal, read on a goroutine of its own so that a
// prompt can give up without the read holding the watcher: a blocking read
// would sit there until somebody typed, so the question's clock would run out
// unnoticed and the next question would not be shown until a keystroke arrived.
//
// One goroutine for the life of the watcher, for the reason there is one
// reader: a second would buffer past the newline and eat the answer to the next
// question.
type typed struct {
	lines chan string
	// paint is the palette the prompt below is printed with. Held here because
	// the prompt is reprinted on every blank line, and the reader is what knows
	// when that happens.
	paint termui.Palette
	// terminal is whether the reader is the operator's own, decided when this was
	// built: the goroutine below holds the reader it started with, and a test
	// substituting another must not make this one flush a terminal it is no
	// longer reading.
	terminal bool
}

func readLines(paint termui.Palette) *typed {
	// Captured, not read through the package variable: the goroutine outlives a
	// test that substituted a reader of its own, and one reading whatever the
	// variable holds now would take the lines meant for whoever set it.
	source, fromTTY := answers, answers == fromTerminal
	t := &typed{lines: make(chan string, 1), terminal: fromTTY, paint: paint}
	go func() {
		defer close(t.lines)
		for {
			line, err := source.ReadString('\n')
			if line != "" {
				t.lines <- line
			}
			if err != nil {
				return
			}
		}
	}()
	return t
}

// discard drops what was typed before the prompt was printed, so that no answer
// is banked against a question nobody had read yet: a line typed while nothing
// was pending would be spent on the next question the instant it arrived.
//
// The terminal's queue and the channel, not the reader's own buffer: the
// goroutine owns that, so touching it from here would be a data race. In
// canonical mode a read returns one line, so the buffer holds nothing the ioctl
// has not already dropped.
//
// This narrows the window rather than closing it: a line the goroutine holds
// between its read and its send lands after the drain.
func (t *typed) discard() {
	if !t.terminal {
		return
	}
	if !flushTypeahead() {
		return
	}
	t.drain()
}

// flushTypeahead drops input that arrived before a prompt was printed, so a
// keystroke meant for something else cannot answer it. This is what makes a
// one-character answer safe, and every prompt taking one has to call it.
//
// Terminals only, and it reports whether it flushed. Input that was not typed
// was not typed early: a substituted reader is a test's script and a redirected
// stdin is a file, and both are meant to be read in order.
func flushTypeahead() bool {
	if !termui.IsTerminal(os.Stdin) {
		return false
	}
	return unix.IoctlSetInt(int(os.Stdin.Fd()), unix.TCFLSH, unix.TCIFLUSH) == nil
}

// drain empties the channel of lines the goroutine has already delivered.
func (t *typed) drain() {
	for {
		select {
		case <-t.lines:
		default:
			return
		}
	}
}

// answerState is how the wait for an answer ended.
type answerState int

const (
	// answered: the operator typed one, and it is the line returned beside this.
	answered answerState = iota
	// expired: the question's clock ran out while the terminal waited. Nothing
	// is sent to the broker, which has already refused it on the way out.
	expired
	// stdinClosed: there is no more input to read, which is the one condition
	// that ends the watch.
	stdinClosed
)

// answer waits for the operator, until the question it is about expires. A
// line holding nothing printable is asked again rather than counted as a no: a
// stray newline is nobody saying anything. Deny by default comes from the
// expiry instead, which the broker applies whether or not this terminal is
// still asking.
func (t *typed) answer(deadline time.Time) (string, answerState) {
	t.discard()
	for {
		// Bold, and the trailing space left outside it: what is being asked for is
		// the last thing on the screen before the cursor, and the cursor sits on a
		// plain space rather than inside a highlight.
		fmt.Print("  " + t.paint.Bold("Approve? [y/n]") + " ")
		select {
		case line, open := <-t.lines:
			if !open {
				return "", stdinClosed
			}
			if answerOf(line) == "" {
				continue
			}
			return line, answered
		case <-time.After(time.Until(deadline)):
			// Anything the goroutine delivered as the clock ran out was typed for the
			// question that just expired, so it goes with it: left in the channel, a
			// yes would approve root for a command nobody answered for.
			t.drain()
			return "", expired
		}
	}
}

// answerOf is the part of a line that carries the answer: what is left once the
// whitespace and unprintable bytes around it are gone. Empty is no answer at
// all. The edges only, so nothing is edited down into an approval it did not
// spell: "y<NUL>e" is a refusal, as it reads.
func answerOf(line string) string {
	return strings.TrimFunc(line, func(r rune) bool {
		return unicode.IsSpace(r) || !unicode.IsPrint(r)
	})
}

// approves is deny by default: only an explicit y approves, and a typo, a
// stray word or a punctuation mark is a no, "yes" among them.
//
// One character, so one keystroke answers the prompt. That is what the flush at
// the top of typed.answer is for: input that arrived before the question was
// shown must not be able to spell the answer to it.
func approves(line string) bool {
	return strings.ToLower(answerOf(line)) == "y"
}

// receivedAt renders the broker's timestamp as a wall clock.
//
// In the zone the broker recorded it in, which the RFC 3339 string carries: the
// broker and whoever is watching are the same host, so that is already the
// terminal's own clock, and converting would be asking the process what zone it
// thinks it is in to arrive back where it started.
//
// A value that will not parse is printed as it arrived rather than dropped: it
// came from the broker, and a question missing the moment it was raised is worse
// than one that looks odd.
func receivedAt(stamp string) string {
	if stamp == "" {
		return "(unknown)"
	}
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return stamp
	}
	return at.Format(auditview.StampLayout)
}

// promptLabelWidth is the widest label below, `received` at eight, plus the
// separating space: every value on the question starts in the same column, and
// pad() renders a label that fills the width with the one space after it.
const promptLabelWidth = 9

// promptField is one line of the question: a label this program owns, then a
// value it does not. Only the label is painted. The broker renders the
// caller's strings before they arrive (see escalation.Command), so colouring a
// value would inject nothing -- but the field boundary is the one thing a
// reader uses to tell faramir's words from the agent's, and a highlight that
// straddles it is the confusion worth engineering. Chrome is coloured, content
// is not, which is also what `faramir logs` does with its fields.
func promptField(paint termui.Palette, label, value string) {
	// Padded before it is painted, as the log's outcome column is: pad() counts
	// escape bytes as width.
	fmt.Printf("  %s%s\n", paint.Key(auditview.Pad(label, promptLabelWidth)), value)
}

// printQuestion shows one question. Every caller-chosen string in it was
// rendered for a terminal by the broker (see escalation.Command), so what
// arrives here holds no escape sequence to obey. One field per line: a question
// is read before it is answered.
func printQuestion(question escalation.Question, paint termui.Palette) {
	// The question without the command, which is the cmd line below: a prompt
	// carrying it too pushes everything worth reading off the screen. Bold
	// because it is the sentence being answered, and everything under it is the
	// evidence: an operator scrolling back is looking for where a question
	// starts.
	fmt.Printf("\n%s\n", paint.Bold(escalation.PromptPrefix))
	// The two ids are dimmed, as `faramir logs` dims the log id in its rows:
	// they are what this question is looked up by afterwards rather than what
	// it is judged on, and the judgement is the cmd, the cwd and the caller.
	promptField(paint, "id", paint.Dim(question.ID))
	// Beside the id, both being the names this question is known by afterwards:
	// the id is what an answer is typed against and stops meaning anything once
	// it is, and the log_id is what the audit log and the `run` record keep. A
	// reader looking one of them up wants the other in the same glance.
	if question.LogID != "" {
		promptField(paint, "log_id", paint.Dim(question.LogID))
	}
	promptField(paint, "cmd", question.Cmd)
	// Directly under the command, being what that command turned out to be: the
	// first thing a reader asks of a question is what is about to run, and the
	// answer is these two lines rather than one of them.
	//
	// Set only when it says something the command does not, which the broker
	// decides: a relative argv[0] resolves against the cwd, and that is a tree
	// the coding agent writes. The resolved path is absolute, so it reads
	// without the cwd beside it; the cwd below explains how it resolved rather
	// than what it is.
	if question.Program != "" {
		promptField(paint, "program", question.Program)
	}
	// The cwd above the host: it is what the command was typed against, and the
	// host is the same on every question a given terminal shows.
	if question.Cwd != "" {
		promptField(paint, "cwd", question.Cwd)
	}
	// Who asked, not who would run it: that is the executor on every question.
	if question.Caller != "" {
		promptField(paint, "caller", question.Caller)
	}
	if question.Host != "" {
		promptField(paint, "host", question.Host)
	}
	// When sudo asked, then what is left of the clock. The wall clock is what
	// puts the question beside everything else stamped in this terminal: a
	// question raised a minute ago and one raised at lunchtime read the same when
	// all that is printed is what remains of the timeout.
	//
	// How long the command has been blocked comes with it, wherever it rounds to
	// a second or more, joined by a comma: the ending this same watcher prints
	// reads "exited 0 in 1.0s (40.0s waiting to be approved, 41.0s total)", and
	// two durations about one question are separated the same way wherever they
	// are printed. Past tense
	// for the same reason: this line is printed once and never rewritten, so the
	// number is what the wait was at the moment it was printed rather than a
	// figure counting up on the screen. Which is not the same as saying nobody
	// was watching: a watcher running the whole time still shows a second here
	// when its own start, the password it was run under, or the poll round trip
	// took that long. The number is the command's wait, not a report on whoever
	// is answering, so it is read at the sizes that mean something.
	waited := ""
	if question.WaitingSec > 0 {
		waited = fmt.Sprintf(", waited %ds", question.WaitingSec)
	}
	promptField(paint, "received", fmt.Sprintf("%s (expires %ds%s)",
		receivedAt(question.Received), question.ExpiresInSec, waited))
}

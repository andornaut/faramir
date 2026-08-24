package main

// faramir sudo ls, approve and deny: the channel an escalation is answered
// on. Three commands rather than one with flags, mirroring the ops the broker
// speaks: `escalations` lists, `approve` says yes, `deny` says no.
//
// Root, and root only. The coding agent runs as the operator, so an escalation
// the operator could give is one the agent could give itself; the broker checks
// SO_PEERCRED on this connection and refuses anything but uid 0. That check is
// the whole boundary, which is why the answer comes back over the broker's own
// socket rather than through systemd-ask-password, whose reply socket's mode is
// a weaker version of the same check.
//
// Blocked here as well as by the broker, so the message says what to do rather
// than arriving as a forbidden from a socket the caller could open.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// watchWait is how long one long poll blocks before asking again. Bounded by
// the broker too: a watcher that never returns cannot notice the broker went
// away.
const watchWait = 60

// requireRootToAnswer refuses a caller that is not root, naming the command it
// was asked of. Stated here as well as at the broker, so the message says what
// to do rather than arriving as a forbidden from a socket the caller could open.
func requireRootToAnswer(command string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	// Not "try sudo": reaching root that way from the account the agent runs as
	// leaves a warm sudo timestamp in a shell the agent can use. The three places
	// named here are the ones warnIfTypeable does not warn about.
	fmt.Fprintf(os.Stderr, "faramir %s must run as root: an escalation has to be answered by an account the "+
		"coding agent cannot become, and it runs as you. Answer from a console, an ssh "+
		"session on another machine, or a login as another account. `sudo` from this shell "+
		"warms a timestamp the agent can spend.\n", command)
	return false
}

// These run one command on its own, which is how the tests reach them without
// going through the root command.
func cmdSudoList(args []string) int  { return runCommand(newSudoListCmd(), args) }
func cmdSudoWatch(args []string) int { return runCommand(newSudoWatchCmd(), args) }
func cmdApprove(args []string) int   { return runCommand(newApproveCmd(), args) }
func cmdReject(args []string) int    { return runCommand(newRejectCmd(), args) }

// newSudoCmd groups everything about a brokered command asking to become root:
// what is waiting, and the three ways an operator answers it.
//
// Named for sudo rather than for escalation because sudo is the word an
// operator reaches for and the one the rest of the install already uses:
// `faramir init --allow-sudo` grants it, and the page that explains it is
// called "Allowing sudo on the controller". The cost is that these need root,
// so the usual form doubles the word.
//
// It runs nothing itself, as the other groups do not: listing is `sudo ls`, so
// that reading and waiting are two verbs rather than one verb and a flag that
// turns it into a different program.
func newSudoCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "sudo",
		Short:   "Approve or refuse a brokered command's request to run sudo",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		RunE:    func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newSudoListCmd(), newSudoWatchCmd(), newApproveCmd(), newRejectCmd())
	return c
}

// newSudoListCmd is what is waiting, printed once. `ls` as the other groups
// spell it.
func newSudoListCmd() *cobra.Command {
	var (
		o    brokerOptions
		when string
	)
	c := &cobra.Command{
		Use:   useLs,
		Short: "List the sudo requests waiting for an answer",
		Long: "Prints what is waiting and exits. Exit status is 0 where something was\n" +
			"waiting, 1 where nothing was, 69 where the broker could not be reached,\n" +
			"which prints nothing rather than an empty list.\n\n" +
			"`faramir sudo watch` is the other form: it waits and answers from that\n" +
			"terminal.",
		Args: noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if !requireRootToAnswer("sudo ls") {
				return codeErr(1)
			}
			paint, err := newPalette(when)
			if err != nil {
				fmt.Fprintf(os.Stderr, "faramir sudo ls: %v\n", err)
				return codeErr(2)
			}
			return codeErr(listEscalations(socketDefault(), o.json, paint))
		},
	}
	o.add(c)
	addColorFlag(c, &when)
	return c
}

// newSudoWatchCmd is the other program: it holds the terminal, reads answers
// from it, and reports how each approved run ended. A verb rather than a flag
// on the listing, which is what it was: waiting for a question, answering it
// and following the run afterwards is not a mode of printing a list.
func newSudoWatchCmd() *cobra.Command {
	var when string
	c := &cobra.Command{
		Use:   "watch",
		Short: "Watch for sudo requests and answer them as they arrive",
		Long: "Holds this terminal: prints each question as it arrives, reads your\n" +
			"answer, and prints how each approved run ended.\n\n" +
			"Run it as root somewhere the coding agent cannot type. The socket check\n" +
			"makes the answer come from root; it cannot make root the one typing.",
		Args: noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if !requireRootToAnswer("sudo watch") {
				return codeErr(1)
			}
			paint, err := newPalette(when)
			if err != nil {
				fmt.Fprintf(os.Stderr, "faramir sudo watch: %v\n", err)
				return codeErr(2)
			}
			return codeErr(watchEscalations(socketDefault(), paint))
		},
	}
	addColorFlag(c, &when)
	return c
}

// newApproveCmd says yes to one question, which has to be named: there is no
// bare `faramir sudo approve`, an escalation naming no command being one nobody
// judged.
func newApproveCmd() *cobra.Command {
	var o brokerOptions
	c := &cobra.Command{
		Use:   "approve [options] ID",
		Short: "Approve one sudo request, by id",
		// The command line before the caller: a malformed one is worth saying
		// whoever is asking, and the other two commands check in that order.
		Args: func(c *cobra.Command, args []string) error {
			if len(args) != 1 || args[0] == "" {
				return usagef("faramir sudo approve: one id is required\nA yes names the command it is for. " +
					"`faramir sudo ls` lists it; `faramir sudo reject` needs no id, one question " +
					"being outstanding at a time")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			if !requireRootToAnswer("sudo approve") {
				return codeErr(1)
			}
			return codeErr(answer("approve", socketDefault(), args[0], true, o.json))
		},
	}
	o.add(c)
	return c
}

// newDenyCmd says no. The id is optional, unlike approving: only one question
// is ever outstanding, and refusing something unseen is safe in a way approving
// it is not, a refusal costing a re-run.
func newRejectCmd() *cobra.Command {
	var (
		o    brokerOptions
		when string
	)
	c := &cobra.Command{
		Use:   "reject [options] [ID]",
		Short: "Refuse one sudo request, or whichever is waiting",
		Args:  atMostOneArg("id"),
		RunE: func(c *cobra.Command, args []string) error {
			if !requireRootToAnswer("sudo reject") {
				return codeErr(1)
			}
			if len(args) == 1 && args[0] != "" {
				return codeErr(answer("reject", socketDefault(), args[0], false, o.json))
			}
			paint, err := newPalette(when)
			if err != nil {
				fmt.Fprintf(os.Stderr, "faramir sudo reject: %v\n", err)
				return codeErr(2)
			}
			return codeErr(rejectWaiting(socketDefault(), o.json, paint))
		},
	}
	o.add(c)
	addColorFlag(c, &when)
	return c
}

// rejectWaiting refuses the one question outstanding, without it having to be
// named. It prints what it refused first, so the scrollback says which command
// was turned down.
func rejectWaiting(socketPath string, asJSON bool, paint palette) int {
	questions, code := waiting(socketPath, "rejected")
	if questions == nil {
		return code
	}
	// Not under --json, where the answer is the whole output and a question
	// printed ahead of it would leave nothing able to parse the result.
	if !asJSON {
		printQuestion(questions[0], paint)
	}
	return answer("deny", socketPath, questions[0].ID, false, asJSON)
}

// waiting is the question outstanding, or nil and the status to exit with: 69
// for a broker that could not be reached, 1 for nothing waiting. One question,
// never a queue, so the caller indexes rather than loops.
func waiting(socketPath, verb string) ([]escalation.Question, int) {
	questions, _, err := pending(socketPath, 0, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir sudo ls: %v\n", err)
		return nil, 69 // EX_UNAVAILABLE, as every other broker-facing command
	}
	if len(questions) == 0 {
		fmt.Fprintf(os.Stderr, "Nothing is waiting to be %s. "+
			"`faramir sudo watch` waits for the next one\n", verb)
		return nil, 1
	}
	return questions, 0
}

// listEscalations reports what is waiting and returns, for a look rather than a
// vigil. Non-zero on nothing waiting, so a script can tell the two apart.
func listEscalations(socketPath string, asJSON bool, paint palette) int {
	questions, code := waiting(socketPath, "approved")
	if asJSON {
		return listAsJSON(questions, code)
	}
	if questions == nil {
		return code
	}
	for _, question := range questions {
		printQuestion(question, paint)
		// The answer is a second command here, so the question says how to type
		// it.
		fmt.Printf("  approve with: faramir sudo approve %s\n", question.ID)
		fmt.Printf("  reject with:  faramir sudo reject %s\n\n", question.ID)
	}
	return 0
}

// listAsJSON is the listing for a caller parsing stdout, carrying the same
// status as the text form. Nothing waiting is an empty array rather than an
// empty stdout, the status saying which it is; a broker that could not be
// reached prints nothing at all, an empty array there saying the host is
// quiet.
func listAsJSON(questions []escalation.Question, code int) int {
	if code == 69 {
		return code
	}
	if questions == nil {
		questions = []escalation.Question{}
	}
	body, err := json.MarshalIndent(questions, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir sudo ls: %v\n", err)
		return 1
	}
	fmt.Println(string(body))
	return code
}

// watchEscalations is the shape an operator leaves running: it blocks until a
// request arrives, shows it, reads the answer from this terminal, and reports
// how an approved run ended. The prompt must not land where the agent can
// type, so run it somewhere the agent does not reach.
func watchEscalations(socketPath string, paint palette) int {
	warnIfTypeable()
	fmt.Fprintln(os.Stderr, "Waiting for escalation requests. Ctrl-c to stop.")
	// No set of ids already answered: the broker drops a question the moment it
	// is answered, refused or expired, and only one is ever outstanding. A set
	// would be worse than unnecessary, an id being three random bytes, so a later
	// question could draw one a stale entry holds and be skipped in silence.
	//
	// awaiting is the run this terminal approved and has not yet heard the end
	// of. One, never a list: an approved run holds every other brokered command
	// until it ends.
	var awaiting string
	terminal := readLines(paint)
	for {
		questions, finished, err := pending(socketPath, watchWait, awaiting)
		if err != nil {
			// Out, rather than reconnecting: a watcher that heals itself is one whose
			// absence is invisible, every question raised while it reconnected
			// expiring unanswered while the terminal still says it is watching. It
			// is also a gap somebody else can arrange, anything that can restart or
			// stall the broker gaining a stretch with no human on the other end.
			//
			// The cost is that `faramir init` restarts the broker, so an install ends
			// a watcher and it has to be started again.
			fmt.Fprintf(os.Stderr, "faramir sudo ls: %v\n", err)
			fmt.Fprintln(os.Stderr, "faramir sudo approve: stopping rather than "+
				"reconnecting: questions raised while nothing was watching would "+
				"expire unanswered. Start it again once the broker is back.")
			return 69 // EX_UNAVAILABLE, as every other broker-facing command
		}
		if finished != nil {
			printOutcome(*finished, paint)
			awaiting = ""
		}
		for _, question := range questions {
			printQuestion(question, paint)
			// The question's own clock, which is what the answer is typed against.
			// Reaching it ends the wait rather than the watch: the broker refused it
			// on the way out, so there is nothing to send.
			line, state := terminal.answer(
				time.Now().Add(time.Duration(question.ExpiresInSec) * time.Second))
			switch state {
			case stdinClosed:
				// Nothing further can be answered here, and leaving the loop spinning
				// would refuse nothing and approve nothing.
				fmt.Fprintln(os.Stderr, "faramir sudo approve: stdin closed; stopping")
				return 0
			case expired:
				fmt.Printf("\n  %s %s\n", paint.dim(question.LogID), paint.bad("expired"))
				continue
			case answered:
			}
			approve := approves(line)
			// The two failures are not alike. 69 is the broker not reached, so the
			// answer was never delivered and the question is open with nobody
			// attending it, which is the silent hole the poll above refuses to leave.
			// 1 is the broker answering no to the answer -- the question expired while
			// it was read, or the yes was refused for want of a quiet host -- so it is
			// settled and gone and watching continues.
			switch code := answer("approve", socketPath, question.ID, approve, false); code {
			case 0:
				// Named, like the ending that follows it: that one arrives after the
				// terminal has moved on, so the two are read together only if both say
				// which run they are about. Only a yes is waited on: a refused run
				// holds nothing once the question is answered, so another command may
				// start and raise the next question.
				if approve {
					awaiting = question.LogID
					// Plain: a run beginning is not an ending, and the line the operator
					// is waiting for is the one that comes after it.
					fmt.Printf("  %s started\n", paint.dim(question.LogID))
					break
				}
				// What it read, on a refusal: an answer nobody typed refuses a question
				// exactly as one they did. Quoted rather than printed, a stray byte
				// being the case this exists for.
				// Painted as a failure for the reason `faramir logs` paints a rejection
				// as one: not because rejecting is wrong, but because something asked.
				fmt.Printf("  %s %s %s\n", paint.dim(question.LogID), paint.bad("rejected:"),
					strconv.Quote(strings.Trim(line, "\r\n")))
			case 69:
				fmt.Fprintf(os.Stderr, "faramir sudo approve: %s could not be answered and is still open with nobody "+
					"watching it. Start this again once the broker is back.\n", question.ID)
				return 69
			default:
				fmt.Fprintf(os.Stderr, "faramir sudo approve: %s was not approved and is now "+
					"closed; run the command again if it still needs to\n", question.ID)
			}
		}
	}
}

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
func printOutcome(outcome escalation.Outcome, paint palette) {
	// The same green and red `faramir logs` gives the outcome column, the same
	// operator reading both: a watcher left running all afternoon is scanned for
	// the endings that were not clean. The log id is dimmed as it is there, and
	// the ending itself carries the colour -- an exit status of 0 is the only
	// green there is, everything else being something that asked to be read.
	id := paint.dim(outcome.LogID)
	switch {
	case outcome.Error != "":
		fmt.Printf("  %s %s\n", id, paint.bad("failed: "+outcome.Error))
	case outcome.ExitCode == nil:
		fmt.Printf("  %s %s\n", id, paint.bad("ended, no exit status"))
	case outcome.TimedOut:
		fmt.Printf("  %s %s\n", id, paint.bad(fmt.Sprintf("exited %d %s, timed out",
			*outcome.ExitCode, ranFor(outcome))))
	default:
		ending := fmt.Sprintf("exited %d %s", *outcome.ExitCode, ranFor(outcome))
		if *outcome.ExitCode != 0 {
			fmt.Printf("  %s %s\n", id, paint.bad(ending))
			break
		}
		fmt.Printf("  %s %s\n", id, paint.ok(ending))
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
	paint palette
	// terminal is whether the reader is the operator's own, decided when this was
	// built: the goroutine below holds the reader it started with, and a test
	// substituting another must not make this one flush a terminal it is no
	// longer reading.
	terminal bool
}

func readLines(paint palette) *typed {
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
	// Terminals only. Input that was not typed was not typed early: a
	// substituted reader is a test's script and a redirected stdin is a file, and
	// both are meant to be read in order.
	if !t.terminal {
		return
	}
	if err := unix.IoctlSetInt(int(os.Stdin.Fd()), unix.TCFLSH, unix.TCIFLUSH); err != nil {
		return
	}
	t.drain()
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
		fmt.Print("  " + t.paint.bold("approve? [y/n]") + " ")
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
	return at.Format(stampLayout)
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
func promptField(paint palette, label, value string) {
	// Padded before it is painted, as the log's outcome column is: pad() counts
	// escape bytes as width.
	fmt.Printf("  %s%s\n", paint.key(pad(label, promptLabelWidth)), value)
}

// printQuestion shows one question. Every caller-chosen string in it was
// rendered for a terminal by the broker (see escalation.Command), so what
// arrives here holds no escape sequence to obey. One field per line: a question
// is read before it is answered.
func printQuestion(question escalation.Question, paint palette) {
	// The question without the command, which is the cmd line below: a prompt
	// carrying it too pushes everything worth reading off the screen. Bold
	// because it is the sentence being answered, and everything under it is the
	// evidence: an operator scrolling back is looking for where a question
	// starts.
	fmt.Printf("\n%s\n", paint.bold(escalation.PromptPrefix))
	// The two ids are dimmed, as `faramir logs` dims the log id in its rows:
	// they are what this question is looked up by afterwards rather than what
	// it is judged on, and the judgement is the cmd, the cwd and the caller.
	promptField(paint, "id", paint.dim(question.ID))
	// Beside the id, both being the names this question is known by afterwards:
	// the id is what an answer is typed against and stops meaning anything once
	// it is, and the log_id is what the audit log and the `run` record keep. A
	// reader looking one of them up wants the other in the same glance.
	if question.LogID != "" {
		promptField(paint, "log_id", paint.dim(question.LogID))
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
	// reads "exited 0 after 41.0s, waited 40s of it", and two durations about one
	// question are separated the same way wherever they are printed. Past tense
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

// pending asks what is waiting, blocking up to waitSec for something to be.
// awaitLogID names the run this caller approved and has not yet heard the end
// of, and is the only run it is told about; empty asks about none.
func pending(socketPath string, waitSec int, awaitLogID string) ([]escalation.Question, *escalation.Outcome, error) {
	request := map[string]any{"op": "escalations"}
	if waitSec > 0 {
		request["wait_sec"] = waitSec
	}
	if awaitLogID != "" {
		request["await_log_id"] = awaitLogID
	}
	// The read deadline has to outlast the broker's own wait, or every long poll
	// looks like a broker that stopped answering.
	line, err := roundTrip(socketPath, request, time.Duration(waitSec+30)*time.Second)
	if err != nil {
		return nil, nil, err
	}
	var response struct {
		Questions []escalation.Question `json:"questions"`
		Finished  *escalation.Outcome   `json:"finished"`
		Error     *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return nil, nil, fmt.Errorf("malformed response: %w", err)
	}
	if response.Error != nil {
		return nil, nil, fmt.Errorf("%s", response.Error.Message)
	}
	return response.Questions, response.Finished, nil
}

func answer(prog, socketPath, id string, approve, asJSON bool) int {
	return send(prog, socketPath, map[string]any{
		"op": "answer", "id": id, "approved": approve,
	}, asJSON, true)
}

// roundTrip is send() for a caller that reads the body itself, and with a
// deadline of its own: the escalations op holds the connection open on
// purpose.
func roundTrip(socketPath string, request map[string]any, timeout time.Duration) ([]byte, error) {
	request["version"] = version.Version
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(
		context.Background(), "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", socketPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := sockutil.Send(conn, request); err != nil {
		return nil, err
	}
	// The write half stays open. The broker reads this connection for the whole
	// of a run and takes an EOF as the caller having gone, killing the command;
	// nothing on this socket half-closes, so there is no per-op rule to get
	// wrong when an op becomes a long one.
	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading the response: %w", err)
	}
	if len(line) == 0 {
		return nil, errors.New("the broker closed the connection without answering")
	}
	return line, nil
}

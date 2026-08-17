package main

// faramir approvals, approve and deny: the channel an approval is answered on.
//
// Three commands rather than one with flags, mirroring the ops the broker
// speaks: `approvals` lists, `approve` says yes, `deny` says no.  One verb
// carrying all three took `--deny`, which reads as its own contradiction, and
// listed when given no argument, which is a verb doing a noun's job.
//
// Root, and root only.  The coding agent runs as the operator, so an approval
// the operator could give is one the agent could give itself; the broker checks
// SO_PEERCRED on this connection and refuses anything but uid 0.  That check is
// the whole boundary, which is why the answer comes back over the broker's own
// socket rather than through systemd-ask-password: that tool cannot be used by
// a broker running as its own uid, and its reply socket's mode is a weaker
// version of the same check.
//
// Refused here as well as by the broker, so the message says what to do rather
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

	"github.com/andornaut/faramir/internal/approval"
	"github.com/andornaut/faramir/internal/sockutil"
)

// watchWait is how long one long poll blocks before asking again.  Bounded by
// the broker too: a watcher that never returns is one that cannot notice the
// broker went away.
const watchWait = 60

// requireRootToAnswer refuses a caller that is not root, naming the command it
// was asked of.  Stated here as well as at the broker, so the message says what
// to do rather than arriving as a forbidden from a socket the caller could open.
func requireRootToAnswer(command string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	// Not "try sudo".  Reaching root that way from the account the agent runs as
	// leaves a warm sudo timestamp in a shell the agent can use, which hands it
	// the account this check exists to keep it out of.  The three places named
	// here are the three warnIfTypeable does not warn about.
	fmt.Fprintf(os.Stderr, "faramir %s must run as root: an approval has to "+
		"be answered by an account the coding agent cannot become, and it runs as "+
		"you. Answer from a console, an ssh session on another machine, or a login "+
		"as another account. Reaching root with `sudo` from this shell warms a sudo "+
		"timestamp the agent can spend, so it is the last resort rather than the "+
		"first.\n", command)
	return false
}

// cmdApprovals, cmdApprove and cmdDeny run one command on its own, which is
// how the tests reach them without going through the root.
func cmdApprovals(args []string) int { return runCommand(newApprovalsCmd(), args) }
func cmdApprove(args []string) int   { return runCommand(newApproveCmd(), args) }
func cmdDeny(args []string) int      { return runCommand(newDenyCmd(), args) }

// newApprovalsCmd lists what is waiting, or waits for it with --watch.  It
// answers nothing: the verbs are their own commands.
func newApprovalsCmd() *cobra.Command {
	var (
		o     brokerOptions
		watch bool
	)
	c := &cobra.Command{
		Use:     "approvals [options]",
		Short:   "list the approval a brokered command is waiting on",
		GroupID: groupProvisioning,
		Args: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("faramir approvals: unexpected argument %q\n"+
					"To answer one: faramir approve ID, or faramir deny ID", args[0])
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			if !requireRootToAnswer("approvals") {
				return codeErr(1)
			}
			if watch {
				return codeErr(watchApprovals(o.socket))
			}
			return codeErr(listApprovals(o.socket, o.json))
		},
	}
	o.add(c)
	c.Flags().BoolVar(&watch, "watch", false,
		"answer questions as they arrive and report how each run ended")
	return c
}

// newApproveCmd says yes to one question, which has to be named.  There is
// deliberately no bare `faramir approve` that says yes to whatever is there: an
// approval that names no command is one nobody judged, which is what this whole
// channel exists to prevent.
func newApproveCmd() *cobra.Command {
	var o brokerOptions
	c := &cobra.Command{
		Use:     "approve [options] ID",
		Short:   "say yes to one, by id",
		GroupID: groupProvisioning,
		// The command line before the caller: a malformed one is worth saying
		// whoever is asking, and the other two commands here check in that order.
		Args: func(c *cobra.Command, args []string) error {
			if len(args) != 1 || args[0] == "" {
				return usagef("faramir approve: one id is required\n" +
					"A yes names the command it is for, so there is no form that approves " +
					"whatever is waiting. `faramir approvals` lists it; `faramir deny` needs " +
					"no id, one question being outstanding at a time")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			if !requireRootToAnswer("approve") {
				return codeErr(1)
			}
			return codeErr(answer("approve", o.socket, args[0], true, o.json))
		},
	}
	o.add(c)
	return c
}

// newDenyCmd says no.  The id is optional, and the asymmetry with approving is
// the point: only one question is ever outstanding, so "the one that is
// waiting" names exactly one thing, and refusing something unseen is safe in a
// way approving it is not.  A refusal costs a re-run.
func newDenyCmd() *cobra.Command {
	var o brokerOptions
	c := &cobra.Command{
		Use:     "deny [options] [ID]",
		Short:   "say no, to that one or to whatever is waiting",
		GroupID: groupProvisioning,
		Args:    atMostOneArg("id"),
		RunE: func(c *cobra.Command, args []string) error {
			if !requireRootToAnswer("deny") {
				return codeErr(1)
			}
			if len(args) == 1 && args[0] != "" {
				return codeErr(answer("deny", o.socket, args[0], false, o.json))
			}
			return codeErr(denyWaiting(o.socket, o.json))
		},
	}
	o.add(c)
	return c
}

// denyWaiting refuses the one question outstanding, without it having to be
// named.  It prints what it refused first, so the operator's own scrollback says
// which command they turned down.
func denyWaiting(socketPath string, asJSON bool) int {
	questions, code := waiting(socketPath, "refused")
	if questions == nil {
		return code
	}
	// Not under --json, where the answer is the whole output and a question
	// printed ahead of it would leave nothing able to parse the result.
	if !asJSON {
		printQuestion(questions[0])
	}
	return answer("deny", socketPath, questions[0].ID, false, asJSON)
}

// waiting is the question outstanding, or nil and the status to exit with: 69
// for a broker that could not be reached, 1 for nothing waiting.  Shared by the
// two one-shot forms, which differ only in the verb they report and in what they
// do with the answer.
//
// One question, never a queue, so the caller indexes rather than loops.
func waiting(socketPath, verb string) ([]approval.Question, int) {
	questions, _, err := pending(socketPath, 0, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir approvals: %v\n", err)
		return nil, 69 // EX_UNAVAILABLE, as every other broker-facing command
	}
	if len(questions) == 0 {
		fmt.Fprintf(os.Stderr, "nothing is waiting to be %s. "+
			"`faramir approvals --watch` waits for the next one\n", verb)
		return nil, 1
	}
	return questions, 0
}

// listApprovals reports what is waiting and returns, for a look rather than a
// vigil.  Non-zero on nothing waiting, so a script can tell the two apart.
func listApprovals(socketPath string, asJSON bool) int {
	questions, code := waiting(socketPath, "approved")
	if asJSON {
		return listAsJSON(questions, code)
	}
	if questions == nil {
		return code
	}
	for _, question := range questions {
		printQuestion(question)
		// The answer is a second command here, so the question says how to type it.
		// What is left of the clock is in the question's own `expires` field, which
		// this form is read against the same as `--watch` is.
		fmt.Printf("  approve with: faramir approve %s\n", question.ID)
		fmt.Printf("  refuse with:  faramir deny %s\n\n", question.ID)
	}
	return 0
}

// listAsJSON is the listing for a caller parsing stdout, carrying the same
// status as the text form.
//
// Nothing waiting is an empty array rather than an empty stdout: a caller
// reading this form gets a value whatever the answer, which is what `faramir
// logs --json` does with a log holding no records.  The status is what says
// which of the two it is, so the array does not have to.
//
// A broker that could not be reached prints nothing at all.  There is no
// listing to report, and an empty array there would say the host is quiet.
func listAsJSON(questions []approval.Question, code int) int {
	if code == 69 {
		return code
	}
	if questions == nil {
		questions = []approval.Question{}
	}
	body, err := json.MarshalIndent(questions, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir approvals: %v\n", err)
		return 1
	}
	fmt.Println(string(body))
	return code
}

// watchApprovals is the shape an operator leaves running: it blocks until a
// request arrives, shows it, reads the answer from this terminal, and reports
// how an approved run ended.  A yes is the last decision made about that
// command, so this is where what it did is said.
//
// This terminal, deliberately.  The prompt must not land where the agent can
// type, so run it somewhere the agent does not reach: not a shell it drives, and
// not a pane of a session it shares.
func watchApprovals(socketPath string) int {
	warnIfTypeable()
	// The one rule the prompt below does not already show: it asks for [yes/no],
	// which reads as though "y" would do and as though only "no" refuses.  What a
	// blank line does, what is discarded, and what prints when a run ends are all
	// visible the moment they happen, so they are not announced in advance.
	fmt.Fprintln(os.Stderr, "waiting for approval requests; only `yes` approves. "+
		"Ctrl-C to stop.")
	// No set of ids already answered, and none is wanted.  The broker drops a
	// question the moment it is answered, refused or expired, and only one is ever
	// outstanding, so a question cannot come back round to be shown twice.  A set
	// would be worse than unnecessary: an id is three random bytes, so a later
	// question can draw one a stale entry still holds and be skipped in silence.
	//
	// awaiting is the run this terminal approved and has not yet heard the end of.
	// One, never a list: an approved run holds every other brokered command until
	// it ends, so a second cannot be in flight, and nothing else can raise a
	// question while this one is going.
	var awaiting string
	terminal := readLines()
	for {
		questions, finished, err := pending(socketPath, watchWait, awaiting)
		if err != nil {
			// Out, rather than reconnecting.  A watcher that heals itself is one whose
			// absence is invisible: every question raised while it was reconnecting
			// expired unanswered, and the terminal went on saying "waiting for approval
			// requests" throughout.  Worse, it is a gap somebody else can arrange --
			// anything that can restart or stall the broker gains a stretch in which no
			// human is on the other end of the question.  Exiting makes the gap the
			// operator's to see and to close.
			//
			// The cost is real: `faramir init` restarts the broker, so an install ends
			// a watcher and it has to be started again.
			fmt.Fprintf(os.Stderr, "faramir approvals: %v\n", err)
			fmt.Fprintln(os.Stderr, "faramir approve: stopping rather than "+
				"reconnecting: questions raised while nothing was watching would "+
				"expire unanswered. Start it again once the broker is back.")
			return 69 // EX_UNAVAILABLE, as every other broker-facing command
		}
		if finished != nil {
			printOutcome(*finished)
			awaiting = ""
		}
		for _, question := range questions {
			printQuestion(question)
			// The question's own clock, which is what the answer is typed against.
			// Reaching it ends the wait rather than the watch: the broker refused it
			// on the way out, so there is nothing to send and the next question is
			// what this terminal is for.
			line, state := terminal.answer(
				time.Now().Add(time.Duration(question.ExpiresInSec) * time.Second))
			switch state {
			case stdinClosed:
				// Nothing further can be answered here, and leaving the loop spinning
				// would refuse nothing and approve nothing.
				fmt.Fprintln(os.Stderr, "faramir approve: stdin closed; stopping")
				return 0
			case expired:
				fmt.Printf("\n  %s expired unanswered, and was refused\n", question.LogID)
				continue
			case answered:
			}
			approve := approves(line)
			// The two failures are not the same and must not be treated alike.
			//
			// 69 is the broker not reached, so the answer was never delivered and the
			// question is still open with nobody attending it.  Carrying on there is
			// the silent hole the poll above refuses to leave: this terminal would go
			// on saying it was watching while the question it had just shown expired
			// unanswered.  So it goes the same way the poll does.
			//
			// 1 is the broker answering no to the answer: the question expired while
			// it was being read, or the yes was refused because the host was not quiet,
			// which closes it rather than holding it open.  Either way it is settled
			// and gone, the broker has already said which, and watching continues.
			switch code := answer("approve", socketPath, question.ID, approve, false); code {
			case 0:
				// Named, like the ending that follows it: that one arrives after the
				// terminal has moved on, so the two are read together only if both say
				// which run they are about.  "started" rather than "approved" for the
				// same reason `faramir logs` says it -- the answer is spent, and what is
				// worth printing is what became of the command.  It pairs with the
				// "exited" below, both being events at a moment.
				//
				// Only a yes is waited on.  A refused run holds nothing once the question
				// is answered, so another command may start and raise the next question,
				// and this terminal has to be back on the poll for it; its ending is in
				// the log like any other command's.
				if approve {
					awaiting = question.LogID
					fmt.Printf("  %s started\n", question.LogID)
					break
				}
				// What it read, on a refusal.  An answer nobody typed refuses a
				// question exactly as one they did, so a refusal that does not say
				// what it was cannot be told from the operator's own no.  Quoted
				// rather than printed: a stray byte is the case this exists for, and
				// it has to be visible rather than acted on by the terminal.
				fmt.Printf("  %s refused: %s\n", question.LogID,
					strconv.Quote(strings.Trim(line, "\r\n")))
			case 69:
				fmt.Fprintf(os.Stderr, "faramir approve: %s could not be answered and is "+
					"still open with nobody watching it; stopping rather than leaving it "+
					"that way. Start this again once the broker is back.\n", question.ID)
				return 69
			default:
				fmt.Fprintf(os.Stderr, "faramir approve: %s was not approved and is now "+
					"closed; run the command again if it still needs to\n", question.ID)
			}
		}
	}
}

// waitedIn is how much of the duration was the question rather than the
// command, where that is worth saying.  The duration is wall time from fork to
// exit and the child sits inside sudo for the whole approval, so a run answered
// after a trip to the kitchen reads as a slow command without it.
//
// Said rather than subtracted: [exec] max_timeout_sec is enforced against the
// same clock the duration measures, and a duration that no longer matched it
// would be a second, quieter number.
func waitedIn(outcome approval.Outcome) string {
	if outcome.WaitedSec < 1 {
		return ""
	}
	// The same precision the duration is printed at: rounded coarser, a wait of
	// 40.6s beside a duration of 41.0s prints as 41 and reads as a command that
	// took no time at all.
	return fmt.Sprintf(", waited %.1fs of it", outcome.WaitedSec)
}

// printOutcome says how the approved run ended, in one line naming the record
// rather than reproducing it: the log holds the command, the refs and the
// output, and this terminal is where the next question has to be readable.
//
// A run with no exit code is said to have ended without one.  Printing a zero
// there would read as a clean exit, which is the one thing this line must not
// get wrong: it is the only report the operator who gave root away receives.
func printOutcome(outcome approval.Outcome) {
	id := outcome.LogID
	switch {
	case outcome.Error != "":
		fmt.Printf("  %s failed: %s\n", id, outcome.Error)
	case outcome.ExitCode == nil:
		fmt.Printf("  %s ended, no exit status\n", id)
	case outcome.TimedOut:
		fmt.Printf("  %s exited %d after %.1fs, timed out%s\n",
			id, *outcome.ExitCode, outcome.DurationSec, waitedIn(outcome))
	default:
		fmt.Printf("  %s exited %d after %.1fs%s\n",
			id, *outcome.ExitCode, outcome.DurationSec, waitedIn(outcome))
	}
}

// warnIfTypeable says so when this terminal is one the coding agent could type
// into.  The socket check makes the answer come from root; it cannot make root
// the one doing the typing.
//
// Two shapes, and the first is the common one:
//
//   - A multiplexer.  tmux and screen keep a per-uid control socket, so any
//     process running as the operator, which is what the agent is, can
//     `tmux send-keys` into this pane.  No sharing is involved and none has to
//     be intended: same uid is the whole requirement.
//   - A tty owned by somebody other than root.  `sudo` leaves the terminal
//     owned by the account that invoked it, so a root process is reading from a
//     device that account still owns.  What that gives an attacker depends on
//     the kernel and on ptrace_scope, which is exactly why it is a warning
//     rather than a claim.
//
// A real console, an ssh session from another machine, or a login as another
// account are the places with neither problem.
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
	fmt.Fprintln(os.Stderr, "\nWARNING: an approval given here may not be yours.")
	for _, reason := range reasons {
		fmt.Fprintln(os.Stderr, "  - "+reason)
	}
	fmt.Fprint(os.Stderr, "The coding agent runs as that account. Watch from a "+
		"console, an ssh session on another machine, or a login as another account "+
		"-- somewhere it cannot reach the keyboard.\n\n")
}

// answers reads the operator's terminal a line at a time.  One reader for the
// life of the watcher: a fresh one per question would buffer past the newline
// and eat the answer to the next.
var answers = bufio.NewReader(os.Stdin)

// fromTerminal is answers as it starts out, compared against once in readLines
// to set the terminal field discard reads.  A test substitutes answers for a
// reader of its own, and scripted answers are read in order rather than
// discarded.
var fromTerminal = answers

// typed is the operator's terminal, read on a goroutine of its own so that a
// prompt can give up without the read holding the watcher.
//
// A blocking read is what a question nobody answers used to cost: the loop sat
// inside it until somebody typed, so the question's own clock ran out unnoticed
// and a question raised after it was not shown until a keystroke arrived. A
// watcher that has stopped watching while still saying it is watching is the
// thing this whole path is careful about, so the read happens elsewhere and the
// loop waits on whichever comes first.
//
// One goroutine for the life of the watcher, for the reason there is one reader:
// a second would buffer past the newline and eat the answer to the next
// question.
type typed struct {
	lines chan string
	// terminal is whether the reader is the operator's own, decided when this was
	// built rather than asked of the package each time: the goroutine below holds
	// the reader it started with, and a test substituting another must not make
	// this one flush a terminal it is no longer reading.
	terminal bool
}

func readLines() *typed {
	// Captured, not read through the package variable.  The goroutine outlives
	// nothing here, but it does outlive a test that substituted a reader of its
	// own, and one reading whatever the variable holds now would take the lines
	// meant for whoever set it.
	source, fromTTY := answers, answers == fromTerminal
	t := &typed{lines: make(chan string, 1), terminal: fromTTY}
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
// is banked against a question nobody had read yet.
//
// Without it a line typed while nothing was pending sits in the terminal until
// the next question arrives and is spent on it the instant it does, which reads
// as an instant refusal of a question the operator never saw.  An answer has to
// be made against a question, so what predates the question is not one.
//
// Two places, and the reader's own buffer is deliberately not one of them: the
// goroutine owns that buffer, so touching it from here would be a data race.
// What is emptied is the terminal's queue and the channel a whole line has
// already reached.  In canonical mode a read returns one line, so the buffer
// holds nothing the ioctl has not already dropped.
//
// This narrows the window rather than closing it: a line the goroutine is
// holding between its read and its send lands after the drain.  What is left is
// those few microseconds, in place of the whole time a question was not yet
// asked.
func (t *typed) discard() {
	// Terminals only, and the channel with them.  Input that was not typed was
	// not typed early: a substituted reader is a test's script and a redirected
	// stdin is a file, and both are meant to be read in order rather than thrown
	// away for having arrived before the prompt.
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
	// expired: the question's clock ran out while the terminal waited.  Nothing
	// is sent to the broker, which has already refused it on the way out.
	expired
	// stdinClosed: there is no more input to read, which is the one condition
	// that ends the watch.
	stdinClosed
)

// answer waits for the operator, until the question it is about expires.
//
// A line holding nothing printable is not an answer and is asked again rather
// than counted as a no: a stray newline is nobody saying anything, and spending
// a question on it answers for an operator who has not read it yet.  Deny by
// default is unchanged and comes from the expiry instead, which the broker
// applies whether or not this terminal is still asking.
func (t *typed) answer(deadline time.Time) (string, answerState) {
	t.discard()
	for {
		fmt.Print("  approve? [yes/no] ")
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
			// Anything the goroutine delivered as the clock ran out was typed for
			// the question that just expired, so it goes with it.  Left in the
			// channel it would be read as the answer to the next one, which for a
			// yes means approving root for a command nobody answered for.
			t.drain()
			return "", expired
		}
	}
}

// answerOf is the part of a line that carries the answer: what is left once the
// whitespace and the unprintable bytes around it are gone.  Empty is no answer
// at all.
//
// The edges only.  A line is stripped of what a terminal puts around an answer
// -- a newline, a carriage return, an escape sequence a keypress left behind --
// and never of what sits inside one, so nothing is edited into a yes it did not
// spell.  "y<NUL>es" is a refusal, as it reads.
func answerOf(line string) string {
	return strings.TrimFunc(line, func(r rune) bool {
		return unicode.IsSpace(r) || !unicode.IsPrint(r)
	})
}

// approves is deny by default, as every other answer path is: only an explicit
// yes approves, and a typo, a stray word or a punctuation mark is a no.
//
// The whole word, not "y".  The prompt above asks for `yes`, and the threat this
// answer is guarded against is a keystroke the operator did not make: a tmux
// pane the agent can `send-keys` into, a tty the operator's own account owns.
// Two bytes rather than four is a thin difference to rest anything on, but a
// tool that accepts less than it asks for is one whose prompt is not the rule.
func approves(line string) bool {
	return strings.ToLower(answerOf(line)) == "yes"
}

// printQuestion shows one question.  Every caller-chosen string in it (the
// command, the cwd, the program) was rendered for a terminal by the broker
// (see approval.Command), so what arrives here holds no escape sequence to obey.
// The fields are printed one per line for the same reason the command is quoted:
// a question is read before it is answered.
func printQuestion(question approval.Question) {
	// The question without the command, which is the cmd line below: a prompt
	// carrying it too says the same thing twice and, for a long one, pushes
	// everything worth reading off the screen.
	fmt.Printf("\n%s\n", approval.PromptPrefix)
	fmt.Printf("  id       %s\n", question.ID)
	fmt.Printf("  cmd      %s\n", question.Cmd)
	// The cwd above the host: it is what the command was typed against, and the
	// host is the same one on every question a given terminal shows.
	if question.Cwd != "" {
		fmt.Printf("  cwd      %s\n", question.Cwd)
	}
	if question.Host != "" {
		fmt.Printf("  host     %s\n", question.Host)
	}
	// Set only when it says something the command does not, which the broker
	// decides: a relative argv[0] resolves against the cwd, and that is a tree the
	// coding agent writes.  Re-deriving the rule here from the rendered command
	// would be a second opinion about it, and the two could disagree.  Printed
	// under the cwd it resolved against, which is what makes it worth reading.
	if question.Program != "" {
		fmt.Printf("  program  %s\n", question.Program)
	}
	if question.LogID != "" {
		fmt.Printf("  log_id   %s\n", question.LogID)
	}
	// What is left of the clock is what the answer is typed against, so it is
	// printed either way.
	//
	// How long it had already sat comes with it rather than on a line of its own,
	// and only where it is not zero.  It is measured when the broker answers the
	// poll, and a watcher already running is answered the moment the question is
	// filed, so zero is the ordinary reading and its absence says as much: what
	// the number is for is the other case, a watcher started while a question was
	// pending or a listing of one that has sat a while.
	waited := ""
	if question.WaitingSec > 0 {
		waited = fmt.Sprintf(" (waited %ds)", question.WaitingSec)
	}
	fmt.Printf("  expires  %ds, after which it is refused%s\n",
		question.ExpiresInSec, waited)
}

// pending asks what is waiting, blocking up to waitSec for something to be.
//
// awaitLogID names the run this caller approved and has not yet heard the end
// of, and is the only run it is told about.  Empty asks about none, which is
// what a listing wants and what a watcher that has approved nothing sends.
func pending(socketPath string, waitSec int, awaitLogID string) ([]approval.Question, *approval.Outcome, error) {
	request := map[string]any{"op": "approvals"}
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
		Questions []approval.Question `json:"questions"`
		Finished  *approval.Outcome   `json:"finished"`
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
		"op": "approve", "id": id, "approve": approve,
	}, asJSON, true)
}

// roundTrip is send() for a caller that reads the body itself, and with a
// deadline of its own: the approvals op holds the connection open on purpose.
func roundTrip(socketPath string, request map[string]any, timeout time.Duration) ([]byte, error) {
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
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading the response: %w", err)
	}
	if len(line) == 0 {
		return nil, errors.New("the broker closed the connection without answering")
	}
	return line, nil
}

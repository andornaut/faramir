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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/brokerclient"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/sudoprompt"
	"github.com/andornaut/faramir/internal/termui"
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
	// named here are the ones sudoprompt.WarnIfTypeable does not warn about.
	fmt.Fprintf(os.Stderr, "faramir %s must run as root, but not by `sudo` from this "+
		"shell: that warms a timestamp the coding agent can spend. Answer from a "+
		"console, an ssh session on another machine, or a login as another account.\n",
		command)
	return false
}

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
			paint, bad := termui.PaletteFor("sudo ls", when)
			if bad != 0 {
				return codeErr(bad)
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
			paint, bad := termui.PaletteFor("sudo watch", when)
			if bad != 0 {
				return codeErr(bad)
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
			return codeErr(answer("sudo approve", socketDefault(), args[0], true, o.json))
		},
	}
	o.add(c)
	return c
}

// newRejectCmd says no. The id is optional, unlike approving: only one question
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
				return codeErr(answer("sudo reject", socketDefault(), args[0], false, o.json))
			}
			paint, bad := termui.PaletteFor("sudo reject", when)
			if bad != 0 {
				return codeErr(bad)
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
func rejectWaiting(socketPath string, asJSON bool, paint termui.Palette) int {
	questions, code := waiting(socketPath, "rejected")
	if questions == nil {
		return code
	}
	// Not under --json, where the answer is the whole output and a question
	// printed ahead of it would leave nothing able to parse the result.
	if !asJSON {
		sudoprompt.PrintQuestion(questions[0], paint)
	}
	return answer("sudo reject", socketPath, questions[0].ID, false, asJSON)
}

// waiting is the question outstanding, or nil and the status to exit with: 69
// for a broker that could not be reached, 1 for nothing waiting. One question,
// never a queue, so the caller indexes rather than loops.
func waiting(socketPath, verb string) ([]escalation.Question, int) {
	questions, _, err := brokerclient.Escalations(socketPath, 0, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir sudo ls: %v\n", err)
		return nil, 69 // EX_UNAVAILABLE, as every other broker-facing command
	}
	if len(questions) == 0 {
		fmt.Fprintf(os.Stderr, "nothing is waiting to be %s; `faramir sudo watch` "+
			"waits for the next one\n", verb)
		return nil, 1
	}
	return questions, 0
}

// listEscalations reports what is waiting and returns, for a look rather than a
// vigil. Non-zero on nothing waiting, so a script can tell the two apart.
func listEscalations(socketPath string, asJSON bool, paint termui.Palette) int {
	questions, code := waiting(socketPath, "approved")
	if asJSON {
		return listAsJSON(questions, code)
	}
	if questions == nil {
		return code
	}
	for _, question := range questions {
		sudoprompt.PrintQuestion(question, paint)
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
	if rc := printJSON("sudo ls", questions); rc != 0 {
		return rc
	}
	return code
}

// watchEscalations is the shape an operator leaves running: it blocks until a
// request arrives, shows it, reads the answer from this terminal, and reports
// how an approved run ended. The prompt must not land where the agent can
// type, so run it somewhere the agent does not reach.
func watchEscalations(socketPath string, paint termui.Palette) int {
	sudoprompt.WarnIfTypeable()
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
	terminal := sudoprompt.ReadLines(paint)
	for {
		questions, finished, err := brokerclient.Escalations(socketPath, watchWait, awaiting)
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
				"reconnecting; start it again once the broker is back")
			return 69 // EX_UNAVAILABLE, as every other broker-facing command
		}
		if finished != nil {
			sudoprompt.PrintOutcome(*finished, paint)
			awaiting = ""
		}
		for _, question := range questions {
			sudoprompt.PrintQuestion(question, paint)
			// The question's own clock, which is what the answer is typed against.
			// Reaching it ends the wait rather than the watch: the broker refused it
			// on the way out, so there is nothing to send.
			line, state := terminal.Answer(
				time.Now().Add(time.Duration(question.ExpiresInSec) * time.Second))
			switch state {
			case sudoprompt.StdinClosed:
				// Nothing further can be answered here, and leaving the loop spinning
				// would refuse nothing and approve nothing.
				fmt.Fprintln(os.Stderr, "faramir sudo approve: stdin closed; stopping")
				return 0
			case sudoprompt.Expired:
				fmt.Printf("\n  %s %s\n", paint.Dim(question.LogID), paint.Bad("expired"))
				continue
			case sudoprompt.Answered:
			}
			approve := termui.Approves(line)
			// The two failures are not alike. 69 is the broker not reached, so the
			// answer was never delivered and the question is open with nobody
			// attending it, which is the silent hole the poll above refuses to leave.
			// 1 is the broker answering no to the answer -- the question expired while
			// it was read, or the yes was refused for want of a quiet host -- so it is
			// settled and gone and watching continues.
			switch code := answer("sudo approve", socketPath, question.ID, approve, false); code {
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
					fmt.Printf("  %s started\n", paint.Dim(question.LogID))
					break
				}
				// What it read, on a refusal: an answer nobody typed refuses a question
				// exactly as one they did. Quoted rather than printed, a stray byte
				// being the case this exists for.
				// Painted as a failure for the reason `faramir logs` paints a rejection
				// as one: not because rejecting is wrong, but because something asked.
				fmt.Printf("  %s %s %s\n", paint.Dim(question.LogID), paint.Bad("rejected:"),
					strconv.Quote(strings.Trim(line, "\r\n")))
			case 69:
				fmt.Fprintf(os.Stderr, "faramir sudo approve: %s is still open and "+
					"unwatched; start this again once the broker is back\n", question.ID)
				return 69
			default:
				fmt.Fprintf(os.Stderr, "faramir sudo approve: %s was not approved "+
					"and is closed; run the command again if it still needs to\n", question.ID)
			}
		}
	}
}

func answer(prog, socketPath, id string, approve, asJSON bool) int {
	return send(prog, socketPath, map[string]any{
		"op": "answer", "id": id, "approved": approve,
	}, asJSON, true)
}

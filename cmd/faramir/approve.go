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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

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
	c.Flags().BoolVar(&watch, "watch", false, "wait for questions and answer them as they arrive")
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
	questions, err := pending(socketPath, 0)
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
	if questions == nil {
		return code
	}
	if asJSON {
		body, _ := json.MarshalIndent(questions, "", "  ")
		fmt.Println(string(body))
		// Same status as the text form.  It said "non-zero on nothing waiting, so a
		// script can tell the two apart" and then returned 0 either way, which is the
		// one form a script would actually be reading.
		if len(questions) == 0 {
			return 1
		}
		return 0
	}
	for _, question := range questions {
		printQuestion(question)
		// The answer is a second command, and the question expires while it is being
		// typed, so the time left is part of the instruction rather than a detail.
		fmt.Printf("  approve with: faramir approve %s\n", question.ID)
		fmt.Printf("  refuse with:  faramir deny %s\n", question.ID)
		fmt.Printf("  within %ds, after which it is refused and the command has to "+
			"be run again\n\n", question.ExpiresInSec)
	}
	return 0
}

// watchApprovals is the shape an operator leaves running: it blocks until a
// request arrives, shows it, and reads the answer from this terminal.
//
// This terminal, deliberately.  The prompt must not land where the agent can
// type, so run it somewhere the agent does not reach: not a shell it drives, and
// not a pane of a session it shares.
func watchApprovals(socketPath string) int {
	warnIfTypeable()
	fmt.Fprintln(os.Stderr, "waiting for approval requests; only `yes` approves, and "+
		"anything else refuses. One command is asked about at a time. Ctrl-C to stop.")
	// No set of ids already answered.  There was one, and it is gone with the
	// queue: a question is removed from the broker the moment it is answered,
	// refused or expired, and only one is ever outstanding, so a question cannot
	// come back round to be shown twice.  What the set did instead was hold stale
	// ids, which are three random bytes, so a later question could draw one and be
	// skipped in silence, and swallow the case below.
	for {
		questions, err := pending(socketPath, watchWait)
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
		for _, question := range questions {
			printQuestion(question)
			approve, ok := readAnswer()
			if !ok {
				// Stdin closed: nothing further can be answered here, and leaving the
				// loop spinning would refuse nothing and approve nothing.
				fmt.Fprintln(os.Stderr, "faramir approve: stdin closed; stopping")
				return 0
			}
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

// readAnswer reads one line and reports what it means.  ok is false only when
// there is no more input to read, which is the one condition that ends the
// watch: everything else, an empty line and a sentence alike, is an answer, and
// every answer that is not yes is a no.
func readAnswer() (approve, ok bool) {
	fmt.Print("  approve? [yes/no] ")
	line, err := answers.ReadString('\n')
	if err != nil && line == "" {
		return false, false
	}
	return approves(line), true
}

// approves is deny by default, as every other answer path is: only an explicit
// yes approves, and a typo, a stray word or an empty line is a no.
//
// The whole word, not "y".  Every prompt says "Type yes", and the threat this
// answer is guarded against is a keystroke the operator did not make: a tmux
// pane the agent can `send-keys` into, a tty the operator's own account owns.
// Two bytes rather than four is a thin difference to rest anything on, but a
// tool that accepts less than it asks for is one whose prompt is not the rule.
func approves(line string) bool {
	return strings.ToLower(strings.TrimSpace(line)) == "yes"
}

// printQuestion shows one question.  Every caller-chosen string in it (the
// command, the cwd, the program) was rendered for a terminal by the broker
// (see approval.Command), so what arrives here holds no escape sequence to obey.
// The fields are printed one per line for the same reason the command is quoted:
// a question is read before it is answered.
func printQuestion(question approval.Question) {
	fmt.Printf("\n%s\n", question.Prompt)
	fmt.Printf("  id       %s\n", question.ID)
	fmt.Printf("  cmd      %s\n", question.Cmd)
	// Set only when it says something the command does not, which the broker
	// decides: a relative argv[0] resolves against the cwd, and that is a tree the
	// coding agent writes.  Re-deriving the rule here from the rendered command
	// would be a second opinion about it, and the two could disagree.
	if question.Program != "" {
		fmt.Printf("  program  %s\n", question.Program)
	}
	if question.Cwd != "" {
		fmt.Printf("  cwd      %s\n", question.Cwd)
	}
	if question.LogID != "" {
		fmt.Printf("  log_id   %s\n", question.LogID)
	}
	fmt.Printf("  waiting  %ds (expires in %ds, then refused)\n",
		question.WaitingSec, question.ExpiresInSec)
}

// pending asks what is waiting, blocking up to waitSec for something to be.
func pending(socketPath string, waitSec int) ([]approval.Question, error) {
	request := map[string]any{"op": "approvals"}
	if waitSec > 0 {
		request["wait_sec"] = waitSec
	}
	// The read deadline has to outlast the broker's own wait, or every long poll
	// looks like a broker that stopped answering.
	line, err := roundTrip(socketPath, request, time.Duration(waitSec+30)*time.Second)
	if err != nil {
		return nil, err
	}
	var response struct {
		Questions []approval.Question `json:"questions"`
		Error     *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return nil, fmt.Errorf("malformed response: %w", err)
	}
	if response.Error != nil {
		return nil, fmt.Errorf("%s", response.Error.Message)
	}
	return response.Questions, nil
}

func answer(prog, socketPath, id string, approve, asJSON bool) int {
	return send(prog, socketPath, map[string]any{
		"op": "approve", "id": id, "approve": approve,
	}, asJSON, true)
}

// roundTrip is send() for a caller that reads the body itself, and with a
// deadline of its own: the approvals op holds the connection open on purpose.
func roundTrip(socketPath string, request map[string]any, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
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
		return nil, fmt.Errorf("the broker closed the connection without answering")
	}
	return line, nil
}

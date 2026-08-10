package main

// faramir approve: the channel an elevation is answered on.
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

	"github.com/andornaut/faramir/internal/elevate"
	"github.com/andornaut/faramir/internal/sockutil"
)

// watchWait is how long one long poll blocks before asking again.  Bounded by
// the broker too: a watcher that never returns is one that cannot notice the
// broker went away.
const watchWait = 60

func cmdApprove(args []string) int {
	fs := newFlagSet("approve", "approve [options] [ID]")
	c := addCommon(fs)
	watch := fs.Bool("watch", false, "wait for requests and answer them as they arrive")
	deny := fs.Bool("deny", false, "refuse the named request rather than approving it")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: faramir approve [options] [ID]")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "faramir approve must run as root: an elevation has to "+
			"be answered by an account the coding agent cannot become, and it runs as "+
			"you. Try 'sudo faramir approve'")
		return 1
	}

	if id := fs.Arg(0); id != "" {
		return answer(*c.socket, id, !*deny, *c.json)
	}
	if *watch {
		return watchApprovals(*c.socket)
	}
	return listApprovals(*c.socket, *c.json)
}

// listApprovals reports what is waiting and returns, for a look rather than a
// vigil.  Non-zero on nothing waiting, so a script can tell the two apart.
func listApprovals(socketPath string, asJSON bool) int {
	questions, err := pending(socketPath, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir approve: %v\n", err)
		return 69 // EX_UNAVAILABLE, as every other broker-facing command
	}
	if asJSON {
		body, _ := json.MarshalIndent(questions, "", "  ")
		fmt.Println(string(body))
		return 0
	}
	if len(questions) == 0 {
		fmt.Fprintln(os.Stderr, "nothing is waiting to be approved. "+
			"`faramir approve --watch` waits for the next one")
		return 1
	}
	for _, question := range questions {
		printQuestion(question)
		fmt.Printf("  answer with: faramir approve %s   (or --deny %s)\n\n",
			question.ID, question.ID)
	}
	return 0
}

// watchApprovals is the shape an operator leaves running: it blocks until a
// request arrives, shows it, and reads the answer from this terminal.
//
// This terminal, deliberately.  The prompt must not land where the agent can
// type, so run it somewhere the agent does not reach -- not a shell it drives,
// and not a pane of a session it shares.
func watchApprovals(socketPath string) int {
	warnIfTypeable()
	fmt.Fprintln(os.Stderr, "waiting for elevation requests; answer each with yes or no. "+
		"Ctrl-C to stop.")
	answered := map[string]bool{}
	for {
		questions, err := pending(socketPath, watchWait)
		if err != nil {
			// The broker is socket-activated and restarted by an install, so a lost
			// connection is ordinary.  Reported and retried rather than fatal: a
			// watcher that exits on the first blip is one nobody notices has gone.
			fmt.Fprintf(os.Stderr, "faramir approve: %v; retrying\n", err)
			time.Sleep(2 * time.Second)
			continue
		}
		for _, question := range questions {
			if answered[question.ID] {
				continue
			}
			printQuestion(question)
			approve, ok := readAnswer()
			if !ok {
				// Stdin closed: nothing further can be answered here, and leaving the
				// loop spinning would refuse nothing and approve nothing.
				fmt.Fprintln(os.Stderr, "faramir approve: stdin closed; stopping")
				return 0
			}
			if code := answer(socketPath, question.ID, approve, false); code != 0 {
				// Usually the question expired while it was being read, or the broker
				// restarted underneath.  Reported and carried on, for the reason the
				// poll above retries: a watcher that exits on the first of these is one
				// nobody notices has gone, and every later request then expires
				// unanswered.  Not marked answered, so a question still waiting is put
				// again rather than skipped.
				fmt.Fprintf(os.Stderr, "faramir approve: %s went unanswered; it may have "+
					"expired while you were reading it\n", question.ID)
				continue
			}
			answered[question.ID] = true
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
//     process running as the operator -- which is what the agent is -- can
//     `tmux send-keys` into this pane.  No sharing is involved and none has to
//     be intended: same uid is the whole requirement.
//   - A tty owned by somebody other than root.  `sudo` leaves the terminal
//     owned by the account that invoked it, so a root process is reading from a
//     device that account still owns.  What that buys an attacker depends on
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
func approves(line string) bool {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "yes", "y":
		return true
	default:
		return false
	}
}

func printQuestion(question elevate.Question) {
	fmt.Printf("\n%s\n", question.Prompt)
	fmt.Printf("  id       %s\n", question.ID)
	if question.Cwd != "" {
		fmt.Printf("  cwd      %s\n", question.Cwd)
	}
	if question.LogID != "" {
		fmt.Printf("  log_id   %s\n", question.LogID)
	}
	fmt.Printf("  waiting  %ds\n", question.WaitingSec)
}

// pending asks what is waiting, blocking up to waitSec for something to be.
func pending(socketPath string, waitSec int) ([]elevate.Question, error) {
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
		Questions []elevate.Question `json:"questions"`
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

func answer(socketPath, id string, approve, asJSON bool) int {
	return send(socketPath, map[string]any{
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

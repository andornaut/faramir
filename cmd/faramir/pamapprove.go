package main

// faramir pam-approve: the authentication step of faramir's own PAM service.
//
// sudo execs this, as root, and reads nothing from it but the exit status: zero
// authenticates the call, anything else refuses it.  So every path here fails
// closed.  There is no password involved anywhere: what it does is ask the
// broker whether the brokered command making this call was approved by a human,
// which is why an approval cannot be carried to a later command: there is
// nothing to carry.
//
// It finds which command is asking by walking /proc up from sudo until it meets
// a process holding FARAMIR_APPROVAL_TOKEN.  PAM does not pass the caller's
// environment to a module, and it does not have to: this runs as root and the
// ancestry is right there.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/approval"
	"github.com/andornaut/faramir/internal/config"
)

// maxAncestors bounds the walk.  A brokered command's tree is a handful deep
// (sudo, a shell, ansible, the command), and a cycle in /proc would otherwise
// spin.
const maxAncestors = 32

// cmdPamApprove runs pam-approve on its own, which is how the tests reach it.
func cmdPamApprove(args []string) int { return runPamApproveCommand(args) }

// runPamApproveCommand applies the rule that nothing but a real approval exits
// 0.  PAM reads the status, so success here is an auth pass: --help and a
// usage error both leave cobra with 0, and 0 is the one thing this helper must
// never say without an approval behind it.  The status is therefore taken from
// whether an approval actually happened, not from how the command returned.
// Neither is reachable through the installed stack, whose argv is fixed, but
// both are closed anyway.
//
// Every caller goes through here: the root registers a command that forwards
// its arguments untouched rather than parsing them itself, so there is one
// path and one place the rule lives.
func runPamApproveCommand(args []string) int {
	granted := false
	code := runCommand(newPamApproveCmd(&granted), args)
	if code == 0 && !granted {
		return 2
	}
	return code
}

type pamApproveFlags struct {
	socket  string
	account string
}

// newPamApproveCmd decides one sudo, setting granted only on the path an
// approval was actually given on.  Run it through runPamApproveCommand, which
// is what reads that.
func newPamApproveCmd(granted *bool) *cobra.Command {
	var f pamApproveFlags
	c := &cobra.Command{
		Use:   "pam-approve",
		Short: "decide one sudo, inside a brokered command (run by PAM)",
		Args:  noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runPamApprove(f, granted))
		},
	}
	c.Flags().StringVar(&f.socket, "socket", socketDefault(), "broker socket to ask")
	c.Flags().StringVar(&f.account, "account", "", "the account this PAM service is for")
	return c
}

func runPamApprove(f pamApproveFlags, granted *bool) int {
	// PAM_TYPE and PAM_USER come from pam_exec.  Checked, so a service file that
	// somebody pointed at another account, or at the account stage rather than
	// auth, cannot authenticate anything.
	if kind := os.Getenv("PAM_TYPE"); kind != "auth" {
		fmt.Fprintf(os.Stderr, "faramir pam-approve: PAM_TYPE is %q; this decides "+
			"authentication and nothing else\n", kind)
		return 1
	}
	if f.account != "" && os.Getenv("PAM_USER") != f.account {
		fmt.Fprintf(os.Stderr, "faramir pam-approve: PAM_USER is %q, not %q: this "+
			"service authenticates one account\n", os.Getenv("PAM_USER"), f.account)
		return 1
	}

	token := findToken()
	if token == "" {
		// Nothing above this call is a brokered command, so there is no run to
		// approve and nobody to ask about.  This is what a `sudo` typed by hand as
		// the executor's account looks like.
		fmt.Fprintln(os.Stderr, "faramir pam-approve: this is not a brokered command, "+
			"so there is nothing for the broker to approve")
		return 1
	}
	approved, reason, err := askBrokerToApprove(f.socket, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir pam-approve: %v\n", err)
		return 1
	}
	if !approved {
		fmt.Fprintf(os.Stderr, "faramir pam-approve: %s\n", reason)
		return 1
	}
	*granted = true
	return 0
}

// findToken walks up from this process until it meets one holding the token a
// brokered command carries.  Root reads any /proc/<pid>/environ, which is one
// of the two reasons the PAM service runs this with seteuid; the other is that
// the broker answers the ask_approval op to root alone, so as the executor's own uid
// this would be refused and no approval on the host would work.
func findToken() string {
	pid := os.Getppid()
	for range maxAncestors {
		if pid <= 1 {
			return ""
		}
		if token := tokenOf(pid); token != "" {
			return token
		}
		parent, ok := parentOf(pid)
		if !ok {
			return ""
		}
		pid = parent
	}
	return ""
}

func tokenOf(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return ""
	}
	for entry := range strings.SplitSeq(string(data), "\x00") {
		if value, found := strings.CutPrefix(entry, approval.TokenEnv+"="); found {
			return value
		}
	}
	return ""
}

// parentOf reads the ppid out of /proc/<pid>/stat.  The fields before it can
// contain spaces and parentheses (the executable name is field two, in
// brackets), so the scan starts after the last ')'.
func parentOf(pid int) (int, bool) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(string(data)[end+1:])
	// state, ppid: the two fields after the name.
	if len(fields) < 2 {
		return 0, false
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, false
	}
	return parent, true
}

// askBrokerToApprove puts the question and waits for the answer, which is a
// human's.  No deadline of its own: the broker holds the question for [sudo]
// timeout_sec and refuses it after that, so a wait here always ends.
func askBrokerToApprove(socketPath, token string) (bool, string, error) {
	line, err := roundTrip(socketPath, map[string]any{"op": "ask_approval", "token": token}, approvalWait)
	if err != nil {
		return false, "", err
	}
	var response struct {
		Approved bool   `json:"approved"`
		Reason   string `json:"reason"`
		Error    *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return false, "", errors.New("malformed response")
	}
	if response.Error != nil {
		return false, "", fmt.Errorf("%s", response.Error.Message)
	}
	return response.Approved, response.Reason, nil
}

// approvalWait is the ceiling on one question: the broker is what decides when
// to give up, and this only stops a lost connection from holding sudo open for
// ever.
//
// Derived rather than picked, and that is the whole point of it.  Two rules pull
// in opposite directions.  It must outlast any question the broker will hold,
// or the helper gives up on a question still open and the operator's yes lands
// on a sudo that has already gone; and it must be short, because until it fires
// sudo is blocked, the run holds its slot, and the host refuses every other
// brokered command.  A constant chosen by hand satisfies the first by being
// absurd about the second: this was two hours against a default question of two
// minutes, so a broker that died without closing the socket held a sudo for the
// rest of the afternoon.
//
// So it is [sudo] timeout_sec's own ceiling plus a margin for the round trip.
// The helper cannot read the config (PAM gives it no environment and its argv
// is fixed at install time), and config.MaxSudoTimeoutSec is what makes reading
// it unnecessary: the broker refuses to load a longer timeout, so the broker
// always decides first and this never fires on a question that is still alive.
const approvalMarginSec = 30

var approvalWait = time.Duration(config.MaxSudoTimeoutSec+approvalMarginSec) * time.Second

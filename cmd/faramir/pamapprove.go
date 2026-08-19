package main

// faramir pam-approve: the authentication step of faramir's own PAM service.
//
// sudo execs this, as root, and reads nothing from it but the exit status: zero
// authenticates the call, anything else refuses it, so every path here fails
// closed. No password is involved: it asks the broker whether the brokered
// command making this call was approved by a human, which is why an escalation
// cannot be carried to a later command.
//
// It finds which command is asking by walking /proc up from sudo until it meets
// a process holding FARAMIR_ESCALATION_TOKEN. PAM does not pass the caller's
// environment to a module, and it does not have to: this runs as root.

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

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/escalation"
)

// maxAncestors bounds the walk: a brokered command's tree is a handful deep,
// and a cycle in /proc would otherwise spin.
const maxAncestors = 32

// cmdPamApprove runs pam-approve on its own, which is how the tests reach
// it.
func cmdPamApprove(args []string) int { return runPamApproveCommand(args) }

// runPamApproveCommand applies the rule that nothing but a real escalation
// exits 0. PAM reads the status as an auth pass, and --help and a usage error
// both leave cobra with 0, so the status is taken from whether an escalation
// happened rather than from how the command returned.
//
// Every caller goes through here: the root registers a command that forwards
// its arguments untouched, so there is one path and one place the rule lives.
func runPamApproveCommand(args []string) int {
	granted := false
	code := runCommand(newPamApproveCmd(&granted), args)
	if code == 0 && !granted {
		return 2
	}
	return code
}

type pamApproveFlags struct {
	account string
}

// newPamApproveCmd decides one sudo, setting granted only on the path an
// escalation was actually given on. Run it through runPamApproveCommand, which
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
	c.Flags().StringVar(&f.account, "account", "", "the account this PAM service is for")
	return c
}

// pamSocket is the broker this helper asks, and it is the compiled-in path
// rather than socketDefault(): every other subcommand lets $FARAMIR_SOCKET move
// it, and this one runs inside the sudo of the account being decided about,
// whose environment pam_exec hands the module unchanged. A broker named there
// is a broker that caller could have started, and it would answer "approved" to
// every question it was asked. There is no flag either, for the same reason one
// path and one socket is the whole of it.
func pamSocket() string { return defaultSocket }

func runPamApprove(f pamApproveFlags, granted *bool) int {
	// PAM_TYPE and PAM_USER come from pam_exec. Checked, so a service file
	// pointed at another account, or at the account stage rather than auth,
	// cannot authenticate anything.
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
		// Nothing above this call is a brokered command, which is what a `sudo`
		// typed by hand as the executor's account looks like.
		fmt.Fprintln(os.Stderr, "faramir pam-approve: this is not a brokered command, "+
			"so there is nothing for the broker to approve")
		return 1
	}
	approved, reason, err := askBrokerToApprove(pamSocket(), token)
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
// brokered command carries. Root reads any /proc/<pid>/environ, which is one
// of the two reasons the PAM service runs this with seteuid; the other is that
// the broker answers the escalate op to root alone.
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
		if value, found := strings.CutPrefix(entry, escalation.TokenEnv+"="); found {
			return value
		}
	}
	return ""
}

// parentOf reads the ppid out of /proc/<pid>/stat. The executable name is
// field two, in brackets, and can hold spaces and parentheses, so the scan
// starts after the last ')'.
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

// askBrokerToApprove puts the question and waits for a human's answer. No
// deadline of its own: the broker holds the question for [escalation]
// timeout_sec and refuses it after that.
func askBrokerToApprove(socketPath, token string) (bool, string, error) {
	line, err := roundTrip(socketPath, map[string]any{"op": "escalate", "token": token}, escalationWait)
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

// escalationWait is the ceiling on one question: the broker decides when to
// give up, and this only stops a lost connection from holding sudo open for
// ever.
//
// Derived rather than picked. It must outlast any question the broker will
// hold, or the helper gives up on a question still open and the operator's yes
// lands on a sudo that has gone; and it must be short, because until it fires
// sudo is blocked and the host refuses every other brokered command. So it is
// [escalation] timeout_sec's own ceiling plus a margin for the round trip: the
// helper cannot read the config, and the broker refuses to load a longer
// timeout, so the broker always decides first.
const escalationMarginSec = 30

var escalationWait = time.Duration(config.MaxSudoTimeoutSec+escalationMarginSec) * time.Second

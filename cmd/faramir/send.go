package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/brokerclient"
	"github.com/andornaut/faramir/internal/fserr"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// send performs one request/response round trip. prog is the subcommand the
// caller typed, so a diagnostic reads `faramir <cmd>:` like the rest.
// Everything on this side of the socket has already been redacted.
func send(prog, socketPath string, request map[string]any, asJSON, quiet bool) int {
	wait := brokerclient.ResponseWait(request)
	request["version"] = version.Version
	conn, err := (&net.Dialer{Timeout: brokerclient.DialWait}).DialContext(
		context.Background(), "unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", prog, fserr.At(socketPath, err))
		return 69 // EX_UNAVAILABLE
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(wait))

	if err := sockutil.Send(conn, request); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", prog, err)
		return 69
	}
	// The write half stays open, though nothing more is sent down it. It is what
	// tells the broker this caller is still here: a run is killed when its
	// caller's connection goes, and a half-close would read as one, so every
	// brokered command would die the moment it started.
	line, err := sockutil.ReadLine(conn, 1<<26)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// Named apart from a close: the socket is listening and nothing behind it
		// answered, which is a broker that did not come up rather than one that
		// refused.
		fmt.Fprintf(os.Stderr, "faramir %s: the broker did not answer within %s. "+
			"The socket accepts connections even when the daemon failed to start: check "+
			"`systemctl status faramir-broker` and `faramir broker --parse-only`\n",
			prog, wait)
		return 69
	}
	if err != nil || len(line) == 0 {
		fmt.Fprintf(os.Stderr, "faramir %s: broker closed the connection without responding\n", prog)
		return 69
	}

	var response struct {
		ExitCode     *int   `json:"exit_code"`
		Output       string `json:"output"`
		Truncated    bool   `json:"truncated"`
		TimedOut     bool   `json:"timed_out"`
		LogID        string `json:"log_id"`
		InvalidBytes int    `json:"invalid_bytes"`
		// The exit code is a stand-in: the executor did not report a status though
		// the command had already run, so the code is non-zero to avoid reading as
		// a success rather than the status itself.
		StatusUnknown bool `json:"status_unknown"`
		// Why a sudo inside the command was turned down, where one was: sudo
		// reports a refusal and an expiry alike, as its own authentication
		// failure.
		Escalation     string `json:"escalation"`
		EscalationCode string `json:"escalation_code"`
		Redactions     []struct {
			Token string `json:"token"`
			Count int    `json:"count"`
		} `json:"redactions"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: malformed response: %v\n", prog, err)
		return 1
	}

	if asJSON {
		// Re-encoded for readability; the round trip changes nothing.
		var raw any
		if err := json.Unmarshal(line, &raw); err == nil {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			// The round trip cannot fail on the encoding; an error here is the
			// write to stdout, which is not something to discard.
			if err := enc.Encode(raw); err != nil {
				fmt.Fprintf(os.Stderr, "faramir %s: writing output: %v\n", prog, err)
				return 1
			}
		}
		if response.Error != nil {
			return brokerclient.ExitFor(response.Error.Code)
		}
		// The same status the plain form exits with. Without this a converge run
		// reading --json cannot tell a broker with a degraded ref from a healthy
		// one, and a brokered command's own exit status is lost the same way.
		if response.ExitCode != nil {
			return *response.ExitCode
		}
		return 0
	}

	if response.Error != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %s: %s\n", prog, response.Error.Code, response.Error.Message)
		if response.LogID != "" {
			fmt.Fprintf(os.Stderr, "faramir %s: log_id=%s\n", prog, response.LogID)
		}
		return brokerclient.ExitFor(response.Error.Code)
	}

	// A failed write to stdout is an error, not something to discard: a broken
	// pipe means the caller never received the output.
	if _, err := io.WriteString(os.Stdout, response.Output); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: writing output: %v\n", prog, err)
		return 1
	}

	// Outside --quiet, which suppresses the redaction summary rather than this:
	// `faramir run --quiet` is how an agent runs a command, and suppressing this
	// would leave it with sudo's authentication failure and nothing else.
	if response.EscalationCode != "" {
		fmt.Fprintf(os.Stderr, "faramir %s: escalation %s: %s\n",
			prog, response.EscalationCode, response.Escalation)
	}

	// The redaction count is a summary of a command that ran as asked, and is
	// what --quiet suppresses. Everything after it says the output is not what
	// the command produced, so a caller reading it as the command's own would be
	// reading something else: those are reported either way. `faramir run
	// --quiet` is how an agent runs a command, and an agent that is not told
	// cannot ask.
	var notes []string
	if !quiet && len(response.Redactions) > 0 {
		var parts []string
		for _, r := range response.Redactions {
			parts = append(parts, fmt.Sprintf("%s×%d", r.Token, r.Count))
		}
		notes = append(notes, "redacted "+strings.Join(parts, ", "))
	}
	if response.Truncated {
		notes = append(notes, "output truncated")
	}
	// Output that was not text does not survive redaction. Only when a byte was
	// actually replaced, stripping colour being ordinary.
	if response.InvalidBytes > 0 {
		notes = append(notes,
			fmt.Sprintf("%d non-text byte(s) replaced", response.InvalidBytes))
	}
	if response.TimedOut {
		notes = append(notes, "timed out")
	}
	// The command ran but the broker never got its exit status, so the code is
	// a non-zero stand-in rather than the command's own or a signal kill.
	if response.StatusUnknown {
		notes = append(notes, "exit status unknown; the reported code is a stand-in")
	}
	if !quiet && response.LogID != "" {
		notes = append(notes, "log_id="+response.LogID)
	}
	if len(notes) > 0 {
		fmt.Fprintf(os.Stderr, "faramir %s: %s\n", prog, strings.Join(notes, "; "))
	}

	if response.ExitCode != nil {
		return *response.ExitCode
	}
	return 0
}

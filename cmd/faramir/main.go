// Command faramir runs a credential-bearing command through the secrets broker.
//
// Secrets are injected as environment variables only; they are never
// substituted into the command line.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
)

const defaultSocket = "/run/faramir/broker.sock"

// socketDefault lets FARAMIR_SOCKET move every subcommand at once.
func socketDefault() string {
	if v := os.Getenv("FARAMIR_SOCKET"); v != "" {
		return v
	}
	return defaultSocket
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	root := newRootCmd()
	root.SetArgs(args)
	return exitCode(root.Execute())
}

// requireRoot refuses a command that must run as root, naming why and how.  The
// approval commands use requireRootToAnswer instead of this: they must not
// suggest sudo, because a warm sudo timestamp is what their check exists to keep
// out of the agent's reach.
func requireRoot(command, reason string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	fmt.Fprintf(os.Stderr, "faramir %s must run as root, because %s: try 'sudo faramir %s'\n",
		command, reason, command)
	return false
}

// operatorName resolves the account that works in the tree: --agent-user,
// then SUDO_USER so `sudo faramir init` needs no flag, then the caller.
//
// root is not an answer at any position: the tree belongs to somebody, and
// chowning a checkout to root would take it from its owner, so escalating by
// another route means passing --agent-user.
func operatorName(flagValue string) string {
	candidates := []string{flagValue, os.Getenv("SUDO_USER")}
	if current, err := user.Current(); err == nil {
		candidates = append(candidates, current.Username)
	}
	for _, candidate := range candidates {
		if candidate != "" && candidate != "root" {
			return candidate
		}
	}
	return ""
}

// newKeygenCmd mints an age keypair, so a faramir host needs no age binary.  It
// does not replace the sops CLI, which is what edits encrypted files.
func newKeygenCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:     "keygen [-o FILE]",
		Short:   "mint an age keypair for the keeper",
		GroupID: groupOperator,
		Args:    noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if out == "" {
				id, err := age.GenerateX25519Identity()
				if err != nil {
					fmt.Fprintf(os.Stderr, "faramir keygen: %v\n", err)
					return codeErr(1)
				}
				fmt.Print(agekey.Format(id))
				fmt.Fprintf(os.Stderr, "Public key: %s\n", id.Recipient())
				return nil
			}
			// Generate refuses to clobber: overwriting an age key destroys every
			// sops file it was the only recipient for, retroactively.
			recipient, created, err := agekey.Generate(out)
			if err != nil {
				fmt.Fprintf(os.Stderr, "faramir keygen: %v\n", err)
				return codeErr(1)
			}
			// Non-zero on an existing target, so a caller can tell a fresh
			// identity from one that was already there.
			if !created {
				fmt.Fprintf(os.Stderr,
					"faramir keygen: %s exists; refusing to overwrite an age key\n", out)
				fmt.Fprintf(os.Stderr, "Public key: %s\n", recipient)
				return codeErr(1)
			}
			fmt.Fprintf(os.Stderr, "Public key: %s\n", recipient)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "output", "o", "", "write the identity to this file instead of stdout")
	return c
}

// brokerOptions are the flags every broker-facing subcommand shares.
type brokerOptions struct {
	socket string
	json   bool
}

func (o *brokerOptions) add(c *cobra.Command) {
	c.Flags().StringVar(&o.socket, "socket", socketDefault(), "broker socket path ($FARAMIR_SOCKET)")
	c.Flags().BoolVar(&o.json, "json", false, "print the raw response")
}

// opExec is the broker operation that runs a command, which is the one whose
// answer is worth waiting on for longer than a round trip.  Not the name of the
// `exec` subcommand, which is the executor daemon and shares only the spelling.
const opExec = "exec"

func newRunCmd() *cobra.Command {
	var (
		o        brokerOptions
		quiet    bool
		cwd      string
		timeout  int
		envRefs  []string
		envFiles []string
	)
	c := &cobra.Command{
		Use:     "run [options] [--] program [args...]",
		Short:   "run a command with secrets injected",
		GroupID: groupOperator,
		Args: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usagef("faramir run: no command given")
			}
			return nil
		},
		// The program's own flags are its own: pflag stops at the "--", and
		// everything after it is passed through untouched.
		RunE: func(c *cobra.Command, rest []string) error {
			// Files first, so an explicit --env overrides the file.
			refs := map[string]string{}
			for _, path := range envFiles {
				pairs, err := readEnvFile(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "faramir run: %v\n", err)
					return codeErr(2)
				}
				maps.Copy(refs, pairs)
			}
			for _, pair := range envRefs {
				name, uri, ok := strings.Cut(pair, "=")
				if !ok {
					fmt.Fprintln(os.Stderr, "faramir run: --env expects NAME=secret://ref")
					return codeErr(2)
				}
				if err := checkRef(name, uri); err != nil {
					fmt.Fprintf(os.Stderr, "faramir run: --env %v\n", err)
					return codeErr(2)
				}
				refs[name] = uri
			}

			request := map[string]any{"op": opExec, "cmd": rest}
			if len(refs) > 0 {
				request["env_refs"] = refs
			}
			// The caller's own directory unless -C says otherwise: a brokered
			// command runs where it was typed.
			if cwd == "" {
				if here, err := os.Getwd(); err == nil {
					cwd = here
				}
			}
			if cwd != "" {
				request["cwd"] = cwd
			}
			if timeout > 0 {
				request["timeout_sec"] = timeout
			}
			return codeErr(send("run", o.socket, request, o.json, quiet))
		},
	}
	o.add(c)
	c.Flags().BoolVar(&quiet, "quiet", false, "suppress the redaction summary")
	c.Flags().StringVarP(&cwd, "cwd", "C", "", "working directory for the command (default: the caller's)")
	c.Flags().IntVarP(&timeout, "timeout", "t", 0, "timeout in seconds")
	c.Flags().StringArrayVar(&envRefs, "env", nil, "NAME=secret://ref (repeatable)")
	c.Flags().StringArrayVar(&envFiles, "env-file", nil, "file of NAME=secret://ref lines (repeatable)")
	return c
}

// checkRef validates one NAME=secret://ref pair, for both --env and --env-file.
// The error names the variable and never quotes the value: a pasted credential
// is the mistake this exists to prevent, and echoing one puts it in the
// scrollback.
func checkRef(name, uri string) error {
	if !protocol.ValidEnvName(name) {
		// Cutting on "=" would name the variable "export NAME".
		if strings.HasPrefix(name, "export ") {
			return fmt.Errorf("%q is not a usable environment variable name; "+
				`drop the "export", this is not a shell script`, name)
		}
		return fmt.Errorf("%q is not a usable environment variable name", name)
	}
	if !strings.HasPrefix(uri, "secret://") {
		return fmt.Errorf("%s must be a secret:// reference; "+
			"secrets are named here, never pasted", name)
	}
	return nil
}

// readEnvFile reads NAME=secret://ref lines, one per line, # for a comment. The
// file holds refs and never values, so it lives beside the playbook it belongs
// to; the request on the wire is the same either way.
func readEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--env-file %s: %w", path, err)
	}
	refs := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, uri, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected NAME=secret://ref, got %q", path, i+1, line)
		}
		name, uri = strings.TrimSpace(name), strings.TrimSpace(uri)
		// Checked here so the message can name the file and the line.
		if err := checkRef(name, uri); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		// Not last-wins: silently picking one of two is how the wrong credential
		// reaches a host.  An identical repeat is a merge artefact, so it passes.
		if existing, seen := refs[name]; seen && existing != uri {
			return nil, fmt.Errorf("%s:%d: %s is given twice, as %s and %s",
				path, i+1, name, existing, uri)
		}
		refs[name] = uri
	}
	return refs, nil
}

// chunkBytes is how much text one redact request carries.  Well under the
// broker's default max_request_bytes, which applies to the JSON-encoded line: a
// control byte becomes six characters, so this cannot exceed it however badly
// it encodes.
const chunkBytes = 32 << 10

// cmdRedact scrubs text that did not come from a brokered command.  As a filter
// it reads stdin; given a command after --, it runs that command and filters
// what it prints, preserving its exit status.
//
// One failure policy across both shapes, decided by what redaction could do and
// not by which shape asked: text that could not be redacted is never written,
// and the exit status is non-zero.
func newRedactCmd() *cobra.Command {
	var o brokerOptions
	c := &cobra.Command{
		Use:     "redact [options] [-- command [args...]]",
		Short:   "scrub secrets out of text, or out of a command's output",
		GroupID: groupOperator,
		RunE: func(c *cobra.Command, child []string) error {
			if len(child) > 0 {
				return codeErr(redactChild(o.socket, child))
			}
			if err := redactStreamLive(o.socket, os.Stdin, os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
				return codeErr(1)
			}
			return nil
		},
	}
	o.add(c)
	return c
}

// redactChild runs the command with both its streams merged and filtered.
// Merged because the agent reads them as one transcript; separating them would
// reorder what it sees.  stdin is passed through.
func redactChild(socketPath string, argv []string) int {
	cmd := exec.CommandContext(context.Background(), argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	output, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
		return 1
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
		return 127
	}
	streamErr := redactStream(socketPath, output, os.Stdout)
	if streamErr != nil {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", streamErr)
		// Drain, or a child that fills the pipe blocks the Wait below. Discarded
		// rather than written: this is the text that could not be redacted, and the
		// rest of a stream that stopped.
		_, _ = io.Copy(io.Discard, output)
	}
	err = cmd.Wait()

	code := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case err != nil:
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
		code = 1
	}
	// The command still ran, and whatever it changed is changed; what is missing
	// is the part of its output that could not be redacted.  So its own status is
	// kept when it failed, and a success is turned into a failure, because
	// withheld output must not read as a command that printed nothing.  This is
	// what wrap.sh does with the same situation, and now for the same reason.
	if streamErr != nil && code == 0 {
		code = 1
	}
	return code
}

// redactStream sends the input through the broker a chunk at a time, breaking
// on a newline where it can.  ReadSlice rather than ReadBytes, which would grow
// one long line past max_request_bytes.
//
// Every chunk goes down ONE connection, each but the last marked "more".  The
// broker keeps one redactor for that connection, so the tail it holds back
// covers the join: a line longer than a chunk has to be broken mid-line, and a
// value across that break belongs to neither half on its own.  A connection per
// chunk put a seam there that nothing scanned.
//
// A chunk that cannot be redacted is never written, and neither is anything
// after it: the stream stops there and the error says so.  Chunks already
// written were redacted successfully, so they stay: holding them back would
// protect nothing, and buffering to be able to would mean an unbounded buffer
// and no incremental output.  So a failure shows as output that stops early,
// not output that is empty; with the broker down, which fails on the first
// chunk, those are the same thing.
// idleFlushInterval bounds how long buffered output waits when a live stream
// goes quiet below chunkBytes.  Without it a backgrounded command that prints a
// line and then blocks (a dev server's "listening on ..." banner) holds that
// line unshown until it produces a whole chunk or exits, which for a server is
// never.  Short enough to read as immediate, long enough that a burst still
// coalesces into one request.
const idleFlushInterval = 200 * time.Millisecond

// streamer carries the redaction of one stream: the pending bytes, the one
// connection they go down, and where the redacted result is written.  Its rules
// are in redactStream's comment.
type streamer struct {
	stream *redactConn
	out    io.Writer
	buf    []byte
}

func (s *streamer) pending() bool { return len(s.buf) > 0 }

// flush sends the pending bytes.  more false is the last chunk, which releases
// the tail the broker holds back.
func (s *streamer) flush(more bool) error {
	// An empty buffer is nothing to send, except as the last chunk of a stream
	// that has already sent something: that one is what releases the tail.
	if len(s.buf) == 0 && (more || !s.stream.open()) {
		return nil
	}
	text := string(s.buf)
	s.buf = s.buf[:0]
	redacted, err := s.stream.send(text, more)
	if err != nil {
		return fmt.Errorf("withheld %d byte(s) that could not be redacted, "+
			"and stopped there: %w", len(text), err)
	}
	_, writeErr := io.WriteString(s.out, redacted)
	return writeErr
}

// feed folds one ReadSlice result into the stream, sending a chunk when one is
// full.  done is true once the stream is complete or has failed; retErr is what
// redactStream should then return.  line is copied into buf, so it need only be
// valid for the call.
func (s *streamer) feed(line []byte, err error) (done bool, retErr error) {
	// Flushed before the append: a partial buffer plus a full ReadSlice would
	// make one request of nearly twice chunkBytes, and a chunk the broker refuses
	// is now a refused stream.
	if len(s.buf) > 0 && len(s.buf)+len(line) > chunkBytes {
		if flushErr := s.flush(true); flushErr != nil {
			return true, flushErr
		}
	}
	s.buf = append(s.buf, line...)
	// A long line arrives in pieces; send what is there.
	if errors.Is(err, bufio.ErrBufferFull) {
		if flushErr := s.flush(true); flushErr != nil {
			return true, flushErr
		}
		return false, nil
	}
	if len(s.buf) >= chunkBytes {
		if flushErr := s.flush(true); flushErr != nil {
			return true, flushErr
		}
	}
	if err != nil {
		if flushErr := s.flush(false); flushErr != nil {
			return true, flushErr
		}
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		return true, err
	}
	return false, nil
}

func redactStream(socketPath string, in io.Reader, out io.Writer) error {
	reader := bufio.NewReaderSize(in, chunkBytes)
	s := &streamer{stream: &redactConn{socketPath: socketPath}, out: out}
	defer s.stream.close()

	for {
		line, err := reader.ReadSlice('\n')
		if done, retErr := s.feed(line, err); done {
			return retErr
		}
	}
}

// redactStreamLive is redactStream for a stream that must show output as it
// arrives, not only when a chunk fills: the redacted stdout of a backgrounded
// command, which the guard pipes here so its output is scrubbed while it runs.
//
// A reader goroutine, because ReadSlice blocks and a pipe inherited as stdin
// does not take a read deadline (Go leaves it in blocking mode).  It copies each
// read before sending, the ReadSlice slice being valid only until the next read.
// The main loop owns buf and the connection; the goroutine touches neither.  On
// an early return the deferred close(done) frees a goroutine parked on the send,
// and one still parked in ReadSlice ends with the process, this path never being
// drained again the way redactChild drains its child.
func redactStreamLive(socketPath string, in io.Reader, out io.Writer) error {
	reader := bufio.NewReaderSize(in, chunkBytes)
	s := &streamer{stream: &redactConn{socketPath: socketPath}, out: out}
	defer s.stream.close()

	type item struct {
		data []byte
		err  error
	}
	ch := make(chan item, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			line, err := reader.ReadSlice('\n')
			cp := append([]byte(nil), line...)
			select {
			case ch <- item{cp, err}:
			case <-done:
				return
			}
			// ErrBufferFull is not the end: it means a line longer than the buffer
			// has more to come.  Any other error, EOF included, ends the read.
			if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
				return
			}
		}
	}()

	for {
		// Armed only when something is waiting, so a silent stream makes no
		// requests: an empty buffer has nothing to flush and blocks for the next
		// read instead.
		var idle <-chan time.Time
		if s.pending() {
			idle = time.After(idleFlushInterval)
		}
		select {
		case it := <-ch:
			if finished, retErr := s.feed(it.data, it.err); finished {
				return retErr
			}
		case <-idle:
			if err := s.flush(true); err != nil {
				return err
			}
		}
	}
}

// redactConn is the one connection a stream's chunks go down.  Dialed on the
// first chunk rather than up front, so an input that turns out to be empty
// costs no connection and writes no audit record.
type redactConn struct {
	socketPath string
	conn       net.Conn
	lines      *sockutil.LineReader
}

func (rc *redactConn) open() bool { return rc.conn != nil }

func (rc *redactConn) close() {
	if rc.conn != nil {
		_ = rc.conn.Close()
		rc.conn = nil
	}
}

// send writes one chunk and reads its answer.  Strictly alternating, which is
// what keeps the broker's reads and this one a chunk apart rather than
// pipelined into each other.
func (rc *redactConn) send(text string, more bool) (string, error) {
	if rc.conn == nil {
		conn, err := (&net.Dialer{Timeout: dialWait}).DialContext(
			context.Background(), "unix", rc.socketPath)
		if err != nil {
			return "", err
		}
		rc.conn, rc.lines = conn, sockutil.NewLineReader(conn, 1<<26)
	}
	// Per chunk, and refreshed for each: a redact runs no command, so an answer
	// that has not arrived by now is a broker that is not going to send one.  The
	// deadline covers the write as well, this side being the only one that can
	// notice the far end never started.
	_ = rc.conn.SetDeadline(time.Now().Add(quickWait))
	request := map[string]any{"op": "redact", "text": text}
	if more {
		request["more"] = true
	}
	if err := sockutil.Send(rc.conn, request); err != nil {
		return "", err
	}
	if !more {
		// Nothing more is coming, so the write half closes: the broker is done
		// with this connection once it has answered.
		if uc, ok := rc.conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}
	line, err := rc.lines.Next()
	if err != nil {
		// Named, not flattened: an oversized request and a reset connection want
		// different fixes.
		return "", fmt.Errorf("reading the response: %w", err)
	}
	if len(line) == 0 {
		return "", errors.New("broker closed the connection without responding")
	}
	var response struct {
		Output string `json:"output"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return "", fmt.Errorf("malformed response: %w", err)
	}
	if response.Error != nil {
		return "", fmt.Errorf("%s", response.Error.Message)
	}
	return response.Output, nil
}

// call runs a subcommand that takes no arguments of its own.
// newCallCmd builds a subcommand that takes no arguments and asks the broker
// one question.  op is the wire name; the command is spelled with dashes.
func newCallCmd(op, short string) *cobra.Command {
	name := strings.ReplaceAll(op, "_", "-")
	var o brokerOptions
	c := &cobra.Command{
		Use:     name,
		Short:   short,
		GroupID: groupOperator,
		Args:    noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			// Only run has --quiet.
			return codeErr(send(name, o.socket, map[string]any{"op": op}, o.json, true))
		},
	}
	o.add(c)
	return c
}

// Bounds on how long this side waits for the broker.  The socket is systemd's
// and stays listening whether or not the service behind it can start, so a
// broker that never becomes ready accepts the connection and answers nothing:
// without a deadline the caller waits for ever, and for the coding agent that
// is a tool call that never returns.
const (
	// dialWait is reaching the socket, which is local and immediate or broken.
	dialWait = 5 * time.Second
	// quickWait bounds a round trip that runs no command.  Generous next to the
	// microseconds these take, because being refused `busy` is also an answer and
	// arrives just as fast.
	quickWait = 15 * time.Second
	// execGrace is what a brokered command's own timeout is padded by: the broker
	// kills at the timeout and still has to write the record and the response.
	execGrace = 30 * time.Second
	// execCeiling stands in for [exec] max_timeout_sec, which is the server's and
	// cannot be read from here.  Only reached when no -t was given, where the
	// server's own default decides and this is merely the outer bound.
	execCeiling = 3600 * time.Second
)

// responseWait is how long to wait for this request's answer.  A command's own
// timeout is what makes the wait long, so it is what the bound is built from.
func responseWait(request map[string]any) time.Duration {
	if request["op"] != opExec {
		return quickWait
	}
	if seconds, ok := request["timeout_sec"].(int); ok && seconds > 0 {
		return time.Duration(seconds)*time.Second + execGrace
	}
	return execCeiling + execGrace
}

// send performs one request/response round trip.  prog is the subcommand the
// caller typed, so a diagnostic reads `faramir <cmd>:` like the rest.  Everything
// on this side of the socket has already been redacted.
func send(prog, socketPath string, request map[string]any, asJSON, quiet bool) int {
	wait := responseWait(request)
	conn, err := (&net.Dialer{Timeout: dialWait}).DialContext(
		context.Background(), "unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %s: %v\n", prog, socketPath, err)
		return 69 // EX_UNAVAILABLE
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(wait))

	if err := sockutil.Send(conn, request); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", prog, err)
		return 69
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<26)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// Named apart from a close: the socket is listening and nothing behind it
		// answered, which is a broker that did not come up rather than one that
		// refused.
		fmt.Fprintf(os.Stderr, "faramir %s: the broker did not answer within %s. The "+
			"socket is systemd's and listens whether or not the daemon behind it "+
			"started: check `systemctl status faramir-broker` and "+
			"`faramir broker --parse-only`\n", prog, wait)
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
		// Why a sudo inside the command was turned down, where one was. Present
		// only then, and the reason a refusal can be told from an expiry here: both
		// reach the command as sudo's own authentication failure.
		Approval     string `json:"approval"`
		ApprovalCode string `json:"approval_code"`
		Redactions   []struct {
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
		// Re-encoded for readability; a round trip through any changes nothing.
		var raw any
		if err := json.Unmarshal(line, &raw); err == nil {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			// The line came back from Unmarshal, so a round trip cannot fail; printing
			// it as it arrived is the answer if it somehow does.
			if err := enc.Encode(raw); err != nil {
				fmt.Println(string(line))
			}
		}
		if response.Error != nil {
			return 1
		}
		return 0
	}

	if response.Error != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %s: %s\n", prog, response.Error.Code, response.Error.Message)
		if response.LogID != "" {
			fmt.Fprintf(os.Stderr, "faramir %s: log_id=%s\n", prog, response.LogID)
		}
		return 1
	}

	fmt.Print(response.Output)

	if !quiet {
		var notes []string
		if len(response.Redactions) > 0 {
			var parts []string
			for _, r := range response.Redactions {
				parts = append(parts, fmt.Sprintf("%s×%d", r.Token, r.Count))
			}
			notes = append(notes, "redacted "+strings.Join(parts, ", "))
		}
		// Both change what the output means, so they are always reported.
		if response.Truncated {
			notes = append(notes, "output truncated")
		}
		// So does this: output that was not text does not survive redaction, so
		// what arrived is not what the command wrote.  Reported here rather than
		// in the output, which is where an archive would be, and only when a byte
		// was actually replaced: stripping colour is the ordinary case and says
		// nothing about the bytes being lost.
		if response.InvalidBytes > 0 {
			notes = append(notes,
				fmt.Sprintf("%d non-text byte(s) replaced", response.InvalidBytes))
		}
		if response.TimedOut {
			notes = append(notes, "timed out")
		}
		// Ahead of the log_id, and said in full rather than by code: this is the
		// one note that decides whether running the command again is worth
		// anything, and a caller reading it has sudo's account of the same event,
		// which names neither.
		if response.ApprovalCode != "" {
			notes = append(notes,
				fmt.Sprintf("approval %s: %s", response.ApprovalCode, response.Approval))
		}
		if response.LogID != "" {
			notes = append(notes, "log_id="+response.LogID)
		}
		if len(notes) > 0 {
			fmt.Fprintf(os.Stderr, "faramir %s: %s\n", prog, strings.Join(notes, "; "))
		}
	}

	if response.ExitCode != nil {
		return *response.ExitCode
	}
	return 0
}

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
	"math"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/fserr"
	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/secretref"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

const defaultSocket = "/run/faramir/broker.sock"

// The Use line every ls subcommand shares, and the environment a child editor is
// started with. Each is spelled in several commands, so each is spelled once.
const (
	useLs   = "ls [options]"
	envPATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	envLANG = "LANG=C.UTF-8"
)

// socketDefault is where every subcommand looks for the broker, and
// FARAMIR_SOCKET is the only way to move it: no subcommand takes a socket
// flag, an install writing `[server] socket_path` from a fixed run directory
// and one variable moving the lot rather than a flag per command.
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

// requireRoot refuses a command that must run as root, naming why and how. The
// escalation commands use requireRootToAnswer instead: they must not suggest
// sudo, a warm sudo timestamp being what their check exists to keep out of the
// agent's reach.
func requireRoot(command, reason string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	fmt.Fprintf(os.Stderr, "faramir %s must run as root, because %s: try 'sudo faramir %s'\n",
		command, reason, command)
	return false
}

// operatorName resolves the account that works in the tree: --agent-user, then
// $FARAMIR_OPERATOR, then SUDO_USER so `sudo faramir init` needs no flag, then
// the caller. root is not an answer at any position: chowning a checkout to root
// would take it from its owner, so reaching root another way means passing
// --agent-user.
//
// $FARAMIR_OPERATOR outranks SUDO_USER because it is set only inside a brokered
// command, and there sudo's caller is the executor rather than a person: the
// broker writes it from the live config and the grant's env_file carries it
// through to root, which is what etc/sudo-env.tmpl exists to do. Ahead of
// SUDO_USER rather than behind it, unlike the config fallback in
// operatorFromConfig: a stale config should not outrank a person answering in
// the present tense, but a brokered run has no person in SUDO_USER to outrank.
func operatorName(flagValue string) string {
	candidates := []string{flagValue, os.Getenv(protocol.OperatorEnv), os.Getenv("SUDO_USER")}
	if current, err := user.Current(); err == nil {
		candidates = append(candidates, current.Username)
	}
	for _, candidate := range candidates {
		if candidate != "" && !notTheOperator[candidate] {
			return candidate
		}
	}
	return ""
}

// notTheOperator is the accounts that cannot be the answer whichever position
// they arrive in. root chowns a checkout away from its owner; faramir's own
// service accounts hold none of the operator's configuration, and one of them
// reaching this means SUDO_USER was read from a brokered command whose
// $FARAMIR_OPERATOR was missing.
//
// The installed names rather than whatever this host called them: a renamed
// account is covered by $FARAMIR_OPERATOR above, which is a marker rather than a
// name, and a list that has to be right about every host is one that reports a
// wrong answer as a right one.
var notTheOperator = map[string]bool{
	"root":                    true,
	install.DefaultBrokerUser: true,
	install.DefaultKeeperUser: true,
	install.DefaultExecUser:   true,
}

// brokerOptions is what every broker-facing subcommand shares.
type brokerOptions struct {
	json bool
}

func (o *brokerOptions) add(c *cobra.Command) {
	c.Flags().BoolVar(&o.json, "json", false, "print the raw response")
}

// opRun is the broker operation that runs a command, the one whose answer is
// worth waiting on for longer than a round trip. Not the `exec` subcommand,
// which is the executor daemon.
const opRun = "run"

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
		Short:   "Run a command with secrets injected",
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
			refs, err := execRefs(envFiles, envRefs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "faramir run: %v\n", err)
				return codeErr(2)
			}

			request := map[string]any{"op": opRun, "cmd": rest}
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
			// Zero is "name none", which the broker reads as its configured
			// default. Below zero is a value nothing can mean, and taking it as
			// "none" ran the command under a timeout the caller did not ask for.
			if timeout < 0 {
				return usagef("--timeout must not be negative; leave it out for " +
					"the broker's own default")
			}
			if timeout > 0 {
				request["timeout_sec"] = timeout
			}
			return codeErr(send("run", socketDefault(), request, o.json, quiet))
		},
	}
	o.add(c)
	c.Flags().BoolVar(&quiet, "quiet", false, "suppress the redaction summary")
	c.Flags().StringVarP(&cwd, "cwd", "C", "", "working directory for the command (default: the caller's)")
	c.Flags().IntVarP(&timeout, "timeout", "t", 0, "timeout in seconds")
	c.Flags().StringArrayVar(&envRefs, "env", nil,
		"NAME=faramir://ref, or a bare NAME for the ref of that name (repeatable)")
	c.Flags().StringArrayVar(&envFiles, "env-file", nil,
		"file of NAME=faramir://ref lines, or a bare NAME for the ref of that name (repeatable)")
	return c
}

// execRefs is what a command's environment is built from: every --env-file in
// the order it was given, and then every --env, so a flag naming a variable a
// file also names is the one that takes. Its own function so the rule can be
// asserted without a broker to run a command against.
func execRefs(envFiles, envRefs []string) (map[string]string, error) {
	refs := map[string]string{}
	for _, path := range envFiles {
		pairs, err := readEnvFile(path)
		if err != nil {
			return nil, err
		}
		maps.Copy(refs, pairs)
	}
	for _, pair := range envRefs {
		name, uri, ok := strings.Cut(pair, "=")
		if !ok {
			// A name on its own, the same shortcut a bare --env-file line is. Not
			// taken on trust: checkRef holds it to what an environment variable may
			// be called and to what a ref may be, so a word that is neither is
			// refused rather than becoming a ref nothing serves.
			name, uri = pair, "faramir://"+pair
		}
		if err := checkRef(name, uri); err != nil {
			return nil, fmt.Errorf("--env %w", err)
		}
		refs[name] = uri
	}
	return refs, nil
}

// checkRef validates one NAME=faramir://ref pair, for both --env and
// --env-file. The error names the variable and never quotes the value: a
// pasted credential is the mistake this exists to prevent, and echoing one puts
// it in the scrollback.
func checkRef(name, uri string) error {
	if !protocol.ValidEnvName(name) {
		// Cutting on "=" would name the variable "export NAME".
		if strings.HasPrefix(name, "export ") {
			return fmt.Errorf("%q is not a usable environment variable name; "+
				`drop the "export", this is not a shell script`, name)
		}
		// A bare name that is a usable ref and not a usable variable name, which
		// is every ref with a "/" in it and so most of them. The shortcut cannot
		// carry one: it names the variable and the ref with one word, and here
		// they cannot be the same word. Said with the long form, that being what
		// somebody reaching for the shortcut wanted.
		if uri == "faramir://"+name {
			if _, err := secretref.Parse(uri); err == nil {
				return fmt.Errorf("%q is a ref, not a name a variable may have. The "+
					"short form uses one word for both, so a ref spelled like this one "+
					"needs a variable of its own: --env NAME=%s", name, uri)
			}
		}
		return fmt.Errorf("%q is not a usable environment variable name", name)
	}
	if !strings.HasPrefix(uri, "faramir://") {
		return fmt.Errorf("%s must be a faramir:// reference; "+
			"secrets are named here, never pasted", name)
	}
	// The ref itself, not only the scheme. The two namespaces are not the same
	// shape: an environment variable may open with an underscore and a ref may
	// not, so a bare `_NAME` line is a usable variable name whose ref no store
	// can hold. Blocked here, with the file and the line, rather than at the
	// broker with the line long gone.
	if _, err := secretref.Parse(uri); err != nil {
		return fmt.Errorf("%s names %s, which is not a ref a store can hold: "+
			"letters, digits, and then any of . _ - /", name, uri)
	}
	return nil
}

// dropComment cuts a trailing comment: a "#" that follows whitespace, as one
// does in a shell and in most dotenv readers. The whitespace is required, and is
// what keeps this unambiguous. Elsewhere a "#" may be part of a value, and the
// quoting rules that tell those apart are the awkward half of every such parser;
// the right of a line here is a ref, which cannot hold one.
//
// A malformed ref can, though, and cutting "faramir://api#token" at the "#" would
// leave "faramir://api", which may be a ref that exists and holds another
// credential. Written without a space it stays whole and is refused as what it is.
func dropComment(line string) string {
	// From 1: a leading "#" is a whole-line comment, and the caller took it.
	for i := 1; i < len(line); i++ {
		if line[i] == '#' && (line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

// readEnvFile reads NAME=faramir://ref lines, one per line. A line that is only a
// name asks for the ref of that name, NAME meaning NAME=faramir://NAME: naming a
// credential after the variable that carries it is the ordinary case, and writing
// both halves out says the same word twice in the one file that says which
// credentials a run needs.
//
// A comment runs to the end of the line, whole-line or after whitespace; see
// dropComment.
//
// The file holds refs and never values, so it lives beside the playbook it
// belongs to.
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
		line = strings.TrimSpace(dropComment(line))
		name, uri, ok := strings.Cut(line, "=")
		if !ok {
			// A name on its own. Not taken on trust: checkRef below holds it to
			// what an environment variable may be called, so a line that is not a
			// name at all is refused naming this file and this line, as it was when
			// every line had to carry a ref.
			name, uri = line, "faramir://"+line
		}
		name, uri = strings.TrimSpace(name), strings.TrimSpace(uri)
		// Checked here so the message can name the file and the line.
		if err := checkRef(name, uri); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		// Not last-wins: silently picking one of two is how the wrong credential
		// reaches a host. An identical repeat is a merge artefact, so it passes.
		if existing, seen := refs[name]; seen && existing != uri {
			return nil, fmt.Errorf("%s:%d: %s is given twice, as %s and %s",
				path, i+1, name, existing, uri)
		}
		refs[name] = uri
	}
	return refs, nil
}

// chunkBytes is how much text one redact request carries. Well under the
// broker's max_request_bytes, which applies to the JSON-encoded line: a control
// byte becomes six characters, so this cannot exceed it however badly it
// encodes.
const chunkBytes = 32 << 10

// newRedactCmd scrubs text that did not come from a brokered command. As a
// filter it reads stdin; given a command after --, it runs that command and
// filters what it prints, preserving its exit status. One failure policy for
// both shapes: text that could not be redacted is never written, and the exit
// status is non-zero.
//
// It takes no --json. Every other broker op is one request and one response,
// which that flag prints; a redaction is a stream of them, and the output is
// the redacted text rather than a reply to render. A flag accepted here and
// read by nothing said this command had a raw response to show.
func newRedactCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "redact [options] [-- command [args...]]",
		Short:   "Remove secrets from text, or from a command's output",
		GroupID: groupOperator,
		RunE: func(c *cobra.Command, child []string) error {
			if len(child) > 0 {
				return codeErr(redactChild(socketDefault(), child))
			}
			if err := redactStreamLive(socketDefault(), os.Stdin, os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
				return codeErr(1)
			}
			return nil
		},
	}
	return c
}

// redactChild runs the command with both its streams merged and filtered.
// Merged because the agent reads them as one transcript. stdin is passed
// through.
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
		// The path once and what the kernel said: exec.Error carries the name and
		// wraps it in "fork/exec", which is Go's plumbing rather than the reader's.
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", fserr.At(argv[0], err))
		// The shell's two, which `faramir run` gives for the same conditions:
		// 126 for a program that is there and cannot be run, 127 for one that is
		// not there. One number for both had a script reading "not installed"
		// where the file was present and not executable.
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.ENOEXEC) {
			return 126
		}
		return 127
	}
	streamErr := redactStream(socketPath, output, os.Stdout)
	if streamErr != nil {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", streamErr)
		// Drain, or a child that fills the pipe blocks the Wait below. Discarded
		// rather than written: this is the text that could not be redacted.
		_, _ = io.Copy(io.Discard, output)
	}
	err = cmd.Wait()

	code := childExitCode(err)
	if code < 0 {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
		code = 1
	}
	// The command still ran, and what is missing is the part of its output that
	// could not be redacted. Its own status is kept when it failed, and a success
	// becomes a failure: withheld output must not read as a command that printed
	// nothing. wrap.sh does the same.
	if streamErr != nil && code == 0 {
		code = 1
	}
	return code
}

// idleFlushInterval bounds how long buffered output waits when a live stream
// goes quiet below chunkBytes. Without it a backgrounded command that prints a
// line and then blocks holds that line unshown until it produces a whole chunk
// or exits, which for a server is never. Short enough to read as immediate,
// long enough that a burst still coalesces into one request.
const idleFlushInterval = 200 * time.Millisecond

// streamer carries the redaction of one stream: the pending bytes, the one
// connection they go down, and where the redacted result is written.
type streamer struct {
	stream *redactConn
	out    io.Writer
	buf    []byte
}

func (s *streamer) pending() bool { return len(s.buf) > 0 }

// flush sends the pending bytes. more false is the last chunk, which releases
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
// full. done is true once the stream is complete or has failed; retErr is what
// redactStream should then return. line is copied into buf, so it need only be
// valid for the call.
func (s *streamer) feed(line []byte, err error) (done bool, retErr error) {
	// Flushed before the append: a partial buffer plus a full ReadSlice would make
	// one request of nearly twice chunkBytes, which the broker could refuse.
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

// childExitCode is the status faramir should exit with for a child that has
// finished. Nil is a clean exit. An exit status is kept as it is. A signal
// death has no exit status -- ExitError.ExitCode answers -1, which os.Exit
// renders as 255 -- so it is mapped to 128+signal, which is what a shell
// reports and what `faramir run` returns for the same death. A -1 return means
// the error was not a child exit at all, for the caller to report and treat as
// its own failure.
func childExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return -1
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return exitErr.ExitCode()
}

// redactStream sends the input through the broker a chunk at a time, breaking
// on a newline where it can. ReadSlice rather than ReadBytes, which would grow
// one long line past max_request_bytes.
//
// Every chunk goes down one connection, each but the last marked "more". The
// broker keeps one redactor for that connection, so the tail it holds back
// covers the join: a line longer than a chunk is broken mid-line, and a value
// across that break belongs to neither half on its own.
//
// A chunk that cannot be redacted is never written, and neither is anything
// after it. Chunks already written were redacted successfully, so they stay:
// buffering to be able to withhold them would mean an unbounded buffer and no
// incremental output. A failure shows as output that stops early.
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
// arrives rather than only when a chunk fills: the redacted stdout of a
// backgrounded command, which the guard pipes here.
//
// A reader goroutine, because ReadSlice blocks and a pipe inherited as stdin
// does not take a read deadline. It copies each read before sending, the
// ReadSlice slice being valid only until the next read; the main loop owns buf
// and the connection. On an early return the deferred close(done) frees a
// goroutine parked on the send, and one still parked in ReadSlice ends with the
// process.
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
			// ErrBufferFull is not the end: a line longer than the buffer has more to
			// come. Any other error, EOF included, ends the read.
			if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
				return
			}
		}
	}()

	for {
		// Armed only when something is waiting, so a silent stream makes no
		// requests.
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

// redactConn is the one connection a stream's chunks go down. Dialed on the
// first chunk, so an input that turns out to be empty costs no connection and
// writes no audit record.
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

// send writes one chunk and reads its answer, strictly alternating rather than
// pipelined.
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
	// that has not arrived by now is not coming. The deadline covers the write as
	// well.
	_ = rc.conn.SetDeadline(time.Now().Add(quickWait))
	request := map[string]any{"op": "redact", "text": text, "version": version.Version}
	if more {
		request["more"] = true
	}
	if err := sockutil.Send(rc.conn, request); err != nil {
		return "", err
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

// newCallCmd builds a subcommand that takes no arguments and asks the broker
// one question. op is the wire name; the command is spelled with dashes.
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
			return codeErr(send(name, socketDefault(), map[string]any{"op": op}, o.json, true))
		},
	}
	o.add(c)
	return c
}

// Bounds on how long this side waits for the broker. The socket is systemd's
// and stays listening whether or not the service behind it can start, so a
// broker that never becomes ready accepts the connection and answers nothing.
const (
	// dialWait is reaching the socket, which is local and immediate or broken.
	dialWait = 5 * time.Second
	// quickWait bounds a round trip that runs no command.
	quickWait = 15 * time.Second
	// execGrace is what a brokered command's own timeout is padded by: the broker
	// kills at the timeout and still has to write the record and the response.
	execGrace = 30 * time.Second
	// execCeiling stands in for [command] max_timeout_sec, which cannot be read
	// from here. Only reached when no -t was given, where the server's own
	// default decides and this is the outer bound.
	execCeiling = 3600 * time.Second
)

// responseWait is how long to wait for this request's answer. A command's own
// timeout is what makes the wait long, so it is what the bound is built from.
//
// Saturating. A caller may name any positive integer and the broker clamps it to
// [command] max_timeout_sec, but multiplying an unclamped one into a Duration
// overflows int64 nanoseconds somewhere past 292 years, and a deadline built
// from a negative duration is one already past: the request then fails on the
// write with "i/o timeout" and no command runs, which reads as a broker that is
// not there rather than as a number nothing could wait that long for.
func responseWait(request map[string]any) time.Duration {
	if request["op"] != opRun {
		return quickWait
	}
	if seconds, ok := request["timeout_sec"].(int); ok && seconds > 0 {
		if seconds > maxWaitSeconds {
			seconds = maxWaitSeconds
		}
		return time.Duration(seconds)*time.Second + execGrace
	}
	return execCeiling + execGrace
}

// maxWaitSeconds is the largest command timeout responseWait can add execGrace
// to and still hold in a Duration.
const maxWaitSeconds = int(math.MaxInt64/int64(time.Second)) - int(execGrace/time.Second)

// errorExit is the status a refused request exits with. One code is separated
// out: a broker at its concurrency limit refused nothing about the command and
// the same request succeeds a moment later, so a caller driving faramir from a
// script can retry it rather than reading stderr to find out whether it should.
// Every other refusal is 1, the command not having run for a reason retrying
// does not change. An escalation already in flight is deliberately not here:
// docs/design.md has why that one is terminal.
func errorExit(code string) int {
	switch code {
	case "busy":
		return 75 // EX_TEMPFAIL
	// The shell's two, so a script can branch on them the way it does on any
	// other command: 127 for a program that is not there, 126 for one that is
	// and cannot be run. `faramir redact -- command` runs its command itself
	// and has always given these; a brokered run gives them now.
	case "not_found":
		return 127
	case "not_executable":
		return 126
	}
	return 1
}

// send performs one request/response round trip. prog is the subcommand the
// caller typed, so a diagnostic reads `faramir <cmd>:` like the rest.
// Everything on this side of the socket has already been redacted.
func send(prog, socketPath string, request map[string]any, asJSON, quiet bool) int {
	wait := responseWait(request)
	request["version"] = version.Version
	conn, err := (&net.Dialer{Timeout: dialWait}).DialContext(
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
			// The line came back from Unmarshal, so a round trip cannot fail;
			// printing it as it arrived is the answer if it somehow does.
			if err := enc.Encode(raw); err != nil {
				fmt.Println(string(line))
			}
		}
		if response.Error != nil {
			return errorExit(response.Error.Code)
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
		return errorExit(response.Error.Code)
	}

	fmt.Print(response.Output)

	// Outside --quiet, which suppresses the redaction summary rather than this:
	// `faramir run --quiet` is how an agent runs a command, and suppressing this
	// would leave it with sudo's authentication failure and nothing else.
	if response.EscalationCode != "" {
		fmt.Fprintf(os.Stderr, "faramir %s: escalation %s: %s\n",
			prog, response.EscalationCode, response.Escalation)
	}

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
		// So does this: output that was not text does not survive redaction. Only
		// when a byte was actually replaced, stripping colour being ordinary.
		if response.InvalidBytes > 0 {
			notes = append(notes,
				fmt.Sprintf("%d non-text byte(s) replaced", response.InvalidBytes))
		}
		if response.TimedOut {
			notes = append(notes, "timed out")
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

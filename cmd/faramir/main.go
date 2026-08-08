// Command faramir runs a credential-bearing command through the secret broker.
//
// Secrets are injected as environment variables only; they are never
// substituted into the command line.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"strings"

	"filippo.io/age"

	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sharetree"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

const defaultSocket = "/run/faramir/broker.sock"

// socketDefault lets FARAMIR_SOCKET move every subcommand at once.  faramir-mcp
// already honours it, and tests/verify.sh sets it.
func socketDefault() string {
	if v := os.Getenv("FARAMIR_SOCKET"); v != "" {
		return v
	}
	return defaultSocket
}

func main() { os.Exit(run(os.Args[1:])) }

func usage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `usage: faramir <command> [options] [-- program [args...]]

Run a credential-bearing command through the secret broker.

Commands:
  run           run a command with secrets injected
  redact        scrub secrets out of text, or out of a command's output
  list-secrets  list secret refs (names only)
  status        show broker status
  keygen        mint an age keypair for the keeper
  share-tree    make a directory usable by brokered commands (requires root)
  version       print the version and exit

Run "faramir <command> --help" for that command's own options.

Every command that talks to the broker accepts:
  --socket PATH   broker socket (default %s; $FARAMIR_SOCKET)
  --json          print the raw response instead of the output

Name secrets with --env NAME=secret://ref, or --env-file for a file of them.

Secrets are injected as environment variables only; they are never substituted
into the command line.
`, socketDefault())
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	case "-V", "--version", "version":
		fmt.Println("faramir " + version.Version)
		return 0
	case "run":
		return cmdRun(args[1:])
	case "redact":
		return cmdRedact(args[1:])
	case "list-secrets":
		return call("list_secrets", args[1:])
	case "status":
		return call("status", args[1:])
	case "share-tree":
		return cmdShareTree(args[1:])
	case "keygen":
		return cmdKeygen(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "faramir: unknown command %q\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

// newFlagSet builds a subcommand's flag set with a usage line of its own.
// flag's default ("Usage of run:") says nothing about what run takes.
func newFlagSet(name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "usage: faramir %s\n\noptions:\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags runs a subcommand's flag set.  An explicit --help is a request
// that succeeded, so it goes to stdout and exits 0; a bad flag goes to stderr
// and exits 2.  flag writes both through the same handle, so the output is
// captured and routed afterwards.
func parseFlags(fs *flag.FlagSet, args []string) (code int, ok bool) {
	var captured bytes.Buffer
	fs.SetOutput(&captured)
	err := fs.Parse(args)
	switch {
	case err == nil:
		return 0, true
	case errors.Is(err, flag.ErrHelp):
		_, _ = fmt.Fprint(os.Stdout, captured.String())
		return 0, false
	default:
		fmt.Fprint(os.Stderr, captured.String())
		return 2, false
	}
}

// cmdShareTree is the one subcommand that needs root: it changes group
// ownership and modes on directories the caller does not own.  Local, like
// keygen, and never touches the broker.
func cmdShareTree(args []string) int {
	fs := newFlagSet("share-tree", "share-tree [options] DIR [DIR...]")
	operator := fs.String("user", "", "account that works in the tree (default $SUDO_USER)")
	group := fs.String("group", envOr("DEV_GROUP", "dev"), "shared group")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "faramir: share-tree needs a directory")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "faramir: share-tree must run as root: it changes "+
			"group ownership and modes on directories you do not own")
		return 1
	}
	who := operatorName(*operator)
	if who == "" {
		fmt.Fprintln(os.Stderr, "faramir: name the account that works in the tree: "+
			"pass --user, set OPERATOR, or run through sudo so SUDO_USER carries it")
		return 1
	}

	for _, dir := range fs.Args() {
		err := sharetree.Share(sharetree.Options{
			Dir: dir, Operator: who, Group: *group,
			Log: func(line string) { fmt.Fprintln(os.Stderr, line) },
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir: %s: %v\n", dir, err)
			return 1
		}
	}
	fmt.Fprintln(os.Stderr, "\nCheck it from the tree: cd there and run "+
		"`faramir run -- pwd`.  A brokered command runs where its caller was, "+
		"so that is the whole test.")
	return 0
}

// operatorName resolves the account that works in the tree.
//
// OPERATOR before SUDO_USER, matching the install scripts: a configuration
// manager escalates without sudo, so SUDO_USER is unset there and the account
// has to be named some other way.  root is not an answer: the tree belongs to
// somebody, and "root" here would chown a checkout away from its owner.
func operatorName(flagValue string) string {
	for _, candidate := range []string{flagValue, os.Getenv("OPERATOR"), os.Getenv("SUDO_USER")} {
		if candidate != "" && candidate != "root" {
			return candidate
		}
	}
	return ""
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// cmdKeygen mints an age keypair.
//
// This exists so a faramir host needs no age binary: the identity format is
// age's own, and the library that writes it is the one the keeper reads it
// with.  It does not replace the sops CLI, which is what an operator edits
// encrypted files with.
func cmdKeygen(args []string) int {
	fs := newFlagSet("keygen", "keygen [-o FILE]")
	out := fs.String("o", "", "write the identity to this file instead of stdout")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 1
	}
	body := fmt.Sprintf("# public key: %s\n%s\n", id.Recipient(), id)

	if *out == "" {
		fmt.Print(body)
		fmt.Fprintf(os.Stderr, "Public key: %s\n", id.Recipient())
		return 0
	}
	// 0400, and refuse to clobber: overwriting an age key silently destroys
	// every sops file it was the only recipient for, retroactively.
	fh, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintf(os.Stderr, "faramir: %s exists; refusing to overwrite an age key\n", *out)
			return 1
		}
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 1
	}
	if _, err := fh.WriteString(body); err != nil {
		_ = fh.Close()
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 1
	}
	// Report a close error rather than exit 0: the key file would be short, and
	// O_EXCL means the next attempt refuses to overwrite it.
	if err := fh.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Public key: %s\n", id.Recipient())
	return 0
}

// common registers the flags every broker-facing subcommand shares.
type common struct {
	socket *string
	json   *bool
}

func addCommon(fs *flag.FlagSet) common {
	return common{
		socket: fs.String("socket", socketDefault(), "broker socket path ($FARAMIR_SOCKET)"),
		json:   fs.Bool("json", false, "print the raw response"),
	}
}

func cmdRun(args []string) int {
	fs := newFlagSet("run", "run [options] [--] program [args...]")
	c := addCommon(fs)
	quiet := fs.Bool("quiet", false, "suppress the redaction summary")
	cwd := fs.String("cwd", "", "working directory for the command (default: the caller's)")
	fs.StringVar(cwd, "C", "", "working directory for the command (shorthand)")
	timeout := fs.Int("timeout", 0, "timeout in seconds")
	fs.IntVar(timeout, "t", 0, "timeout in seconds (shorthand)")
	var envRefs multiFlag
	fs.Var(&envRefs, "env", "NAME=secret://ref (repeatable)")
	var envFiles multiFlag
	fs.Var(&envFiles, "env-file", "file of NAME=secret://ref lines (repeatable)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	rest := fs.Args()
	// A leading "--" is the habitual spelling and flag has already stopped
	// parsing by the time it reaches us; strip it so both forms work.
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "faramir run: no command given")
		fs.SetOutput(os.Stderr)
		fs.Usage()
		return 2
	}

	// Files first, so an explicit --env on the command line overrides the file
	// rather than the other way round.
	refs := map[string]string{}
	for _, path := range envFiles {
		pairs, err := readEnvFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir run: %v\n", err)
			return 2
		}
		maps.Copy(refs, pairs)
	}
	for _, pair := range envRefs {
		name, uri, ok := strings.Cut(pair, "=")
		if !ok {
			fmt.Fprintln(os.Stderr, "faramir run: --env expects NAME=secret://ref")
			return 2
		}
		if err := checkRef(name, uri); err != nil {
			fmt.Fprintf(os.Stderr, "faramir run: --env %v\n", err)
			return 2
		}
		refs[name] = uri
	}

	request := map[string]any{"op": "exec", "cmd": rest}
	if len(refs) > 0 {
		request["env_refs"] = refs
	}
	// The caller's own directory unless -C says otherwise.  A command run
	// through the broker should run where it was typed, the way every other
	// command does; falling back to a directory named in a config file means
	// "faramir run make" in one checkout builds a different one.
	if *cwd == "" {
		if here, err := os.Getwd(); err == nil {
			*cwd = here
		}
	}
	if *cwd != "" {
		request["cwd"] = *cwd
	}
	if *timeout > 0 {
		request["timeout_sec"] = *timeout
	}
	return send(*c.socket, request, *c.json, *quiet)
}

// checkRef validates one NAME=secret://ref pair, for both --env and
// --env-file, so the two cannot drift apart.
//
// The error never quotes the value.  A pasted credential is the mistake this
// whole mechanism exists to prevent, and an error that echoes one puts it in
// the terminal and the scrollback, which is the disclosure it was meant to
// stop.  The name is safe to quote and is what the operator needs to find the
// line.
func checkRef(name, uri string) error {
	if !protocol.ValidEnvName(name) {
		// "export NAME=..." is the habitual spelling for a file of environment
		// variables, and cutting on "=" turns it into a variable literally
		// named "export NAME".
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

// readEnvFile reads NAME=secret://ref lines, one per line, # for a comment.
//
// A command that needs a dozen credentials otherwise needs a dozen --env flags
// repeated at every call site, which is how one gets quietly dropped.  The file
// holds refs and never values, so it is ordinary reviewable content that lives
// beside the playbook it belongs to; the CLI expands it here and the request on
// the wire is the same either way.
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
		// Checked here rather than by the broker so the message can name the
		// file and the line.
		if err := checkRef(name, uri); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		// Last-wins is the usual env-file rule, but this file names credentials
		// for a fleet: silently picking one of two is how the wrong credential
		// reaches a host.  An identical repeat is a merge artefact, not an
		// ambiguity, so it passes.
		if existing, seen := refs[name]; seen && existing != uri {
			return nil, fmt.Errorf("%s:%d: %s is given twice, as %s and %s",
				path, i+1, name, existing, uri)
		}
		refs[name] = uri
	}
	return refs, nil
}

// chunkBytes is how much text one redact request carries.
//
// Well under the broker's default max_request_bytes (262144) because the limit
// is on the JSON-encoded line, not on the text: a control byte becomes six
// characters and a byte that is not valid UTF-8 becomes three, so a chunk this
// size cannot exceed the limit however badly it encodes.
const chunkBytes = 32 << 10

// cmdRedact scrubs text that did not come from a brokered command.
//
// Two shapes.  As a filter it reads stdin and writes redacted stdout.  Given a
// command after --, it runs that command and filters what it prints, which is
// the shape the PreToolUse hook rewrites an agent's shell command into: the
// child's exit status is preserved, so the caller cannot tell the difference
// except that secrets come back as tokens.
func cmdRedact(args []string) int {
	fs := newFlagSet("redact", "redact [options] [-- command [args...]]")
	c := addCommon(fs)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if child := fs.Args(); len(child) > 0 {
		return redactChild(*c.socket, child)
	}
	if err := redactStream(*c.socket, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
		return 1
	}
	return 0
}

// redactChild runs the command with both its streams merged and filtered.
//
// Merged because the two are interleaved on a terminal anyway and the agent
// reads them as one transcript; separating them here would reorder the output
// it sees.  stdin is passed through, so a wrapped command that reads input
// still works.
func redactChild(socketPath string, argv []string) int {
	cmd := exec.Command(argv[0], argv[1:]...)
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
		// Drain, or a child that fills the pipe blocks forever and the Wait
		// below never returns.
		_, _ = io.Copy(io.Discard, output)
	}
	err = cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
		return 1
	}
	return 0
}

// redactStream sends the input through the broker a chunk at a time.
//
// Chunks break on a newline where they can, so a value is not split across two
// requests and missed for that reason.  Two cases still split one: a value that
// itself spans lines (a PEM block), and a line longer than a chunk.  The second
// is why ReadSlice is used rather than ReadBytes: ReadBytes grows until it
// finds a newline, so one long line (a -vvv result dict, minified JSON) would
// arrive as a single request over max_request_bytes and be refused whole.
//
// A failed chunk is passed through unredacted and the next chunk is still
// attempted.  Giving up after the first failure would hand the entire rest of
// the output over untouched, which is a much larger hole than the chunk that
// actually failed, and the warning is printed once so a long stream does not
// bury its own output.
func redactStream(socketPath string, in io.Reader, out io.Writer) error {
	reader := bufio.NewReaderSize(in, chunkBytes)
	buf := make([]byte, 0, chunkBytes)
	warned := false

	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		text := string(buf)
		buf = buf[:0]
		redacted, err := redactOnce(socketPath, text)
		if err != nil {
			if !warned {
				warned = true
				fmt.Fprintf(os.Stderr,
					"faramir redact: passing output through unredacted: %v\n", err)
			}
			_, writeErr := io.WriteString(out, text)
			return writeErr
		}
		_, writeErr := io.WriteString(out, redacted)
		return writeErr
	}

	for {
		line, err := reader.ReadSlice('\n')
		// Flushed before the append, not after: a partial buffer plus a full
		// ReadSlice would otherwise make one request of nearly twice
		// chunkBytes, and chunkBytes is the size that keeps the encoded line
		// inside max_request_bytes.  Over it the broker refuses the chunk and
		// the text is passed through unredacted.
		if len(buf) > 0 && len(buf)+len(line) > chunkBytes {
			if flushErr := flush(); flushErr != nil {
				return flushErr
			}
		}
		buf = append(buf, line...)
		// A line longer than the buffer arrives in pieces, so send what is
		// there rather than growing without bound.
		if errors.Is(err, bufio.ErrBufferFull) {
			if flushErr := flush(); flushErr != nil {
				return flushErr
			}
			continue
		}
		if len(buf) >= chunkBytes {
			if flushErr := flush(); flushErr != nil {
				return flushErr
			}
		}
		if err != nil {
			if flushErr := flush(); flushErr != nil {
				return flushErr
			}
			if errors.Is(err, io.EOF) {
				// A redaction failure was already reported, once, by flush.
				// Returning it as well would print it twice and turn a pipeline
				// that did pass its text through into a failure.
				return nil
			}
			return err
		}
	}
}

func redactOnce(socketPath, text string) (string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	if err := sockutil.Send(conn, map[string]any{"op": "redact", "text": text}); err != nil {
		return "", err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<26)
	if err != nil {
		// Named, not flattened: a refused oversized request and a reset
		// connection want different fixes, and reporting both as a silent
		// hang-up sends the reader after the wrong one.
		return "", fmt.Errorf("reading the response: %w", err)
	}
	if len(line) == 0 {
		return "", fmt.Errorf("broker closed the connection without responding")
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
func call(op string, args []string) int {
	name := strings.ReplaceAll(op, "_", "-")
	fs := newFlagSet(name, name+" [options]")
	c := addCommon(fs)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if rest := fs.Args(); len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "faramir %s: unexpected argument %q\n", name, rest[0])
		return 2
	}
	// Only run has --quiet; the others never print a summary anyway.
	return send(*c.socket, map[string]any{"op": op}, *c.json, true)
}

// send performs one request/response round trip.  No secret logic lives on
// this side of the socket: everything it can see has already been redacted.
func send(socketPath string, request map[string]any, asJSON, quiet bool) int {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %s: %v\n", socketPath, err)
		return 69 // EX_UNAVAILABLE
	}
	defer func() { _ = conn.Close() }()

	if err := sockutil.Send(conn, request); err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 69
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<26)
	if err != nil || len(line) == 0 {
		fmt.Fprintln(os.Stderr, "faramir: broker closed the connection without responding")
		return 69
	}

	var response struct {
		ExitCode   *int   `json:"exit_code"`
		Output     string `json:"output"`
		Truncated  bool   `json:"truncated"`
		TimedOut   bool   `json:"timed_out"`
		LogID      string `json:"log_id"`
		Redactions []struct {
			Token string `json:"token"`
			Count int    `json:"count"`
		} `json:"redactions"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		fmt.Fprintf(os.Stderr, "faramir: malformed response: %v\n", err)
		return 1
	}

	if asJSON {
		// Re-encode rather than echoing the line: indented output is readable
		// at a terminal, and a round trip through any is still exactly the
		// values the broker sent.
		var raw any
		if err := json.Unmarshal(line, &raw); err == nil {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			_ = enc.Encode(raw)
		}
		if response.Error != nil {
			return 1
		}
		return 0
	}

	if response.Error != nil {
		fmt.Fprintf(os.Stderr, "faramir: %s: %s\n", response.Error.Code, response.Error.Message)
		if response.LogID != "" {
			fmt.Fprintf(os.Stderr, "faramir: log_id=%s\n", response.LogID)
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
		// Both of these change what the output means, so they are reported
		// even when nothing was redacted.
		if response.Truncated {
			notes = append(notes, "output truncated")
		}
		if response.TimedOut {
			notes = append(notes, "timed out")
		}
		if response.LogID != "" {
			notes = append(notes, "log_id="+response.LogID)
		}
		if len(notes) > 0 {
			fmt.Fprintf(os.Stderr, "[faramir] %s\n", strings.Join(notes, "; "))
		}
	}

	if response.ExitCode != nil {
		return *response.ExitCode
	}
	return 0
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// Command faramir runs a credential-bearing command through the secrets broker.
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
	"os/user"
	"strings"

	"filippo.io/age"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/guard"
	"github.com/andornaut/faramir/internal/mcp"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
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

func usage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `usage: faramir <command> [options] [-- program [args...]]

A secrets broker for local AI coding agents: it runs the commands that need
credentials and keeps the values out of the agent's context.

Commands:
  run           run a command with secrets injected
  redact        scrub secrets out of text, or out of a command's output
  list-secrets  list secret refs (names only)
  status        show broker status
  keygen        mint an age keypair for the keeper
  version       print the version and exit

Provisioning (require root; they do not talk to the broker):
  init          install or re-install faramir on this host
  init-project  enrol one working tree: share it, and configure the agent there
  edit          edit a managed sops file
  logs          show the audit log: what ran, against which refs, and how it ended
  doctor        report whether the install is doing its job
  reload        drop the daemons onto a changed configuration
  uninstall     remove the broker, keeping the key, the store and the log

Run by systemd and by the coding agent, not by you:
  broker        the secrets broker daemon
  keeper        holds the age key, serves decrypted values
  exec          the executor daemon (to run a command, see "run" above)
  mcp           MCP stdio server
  guard         PreToolUse hook

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
	case "keygen":
		return cmdKeygen(args[1:])
	case "init":
		return cmdInit(args[1:])
	case "init-project":
		return cmdInitProject(args[1:])
	case "edit":
		return cmdEdit(args[1:])
	case "logs":
		return cmdLogs(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "reload":
		return cmdReload(args[1:])
	case "uninstall":
		return cmdUninstall(args[1:])
	// The roles systemd and the coding agent run, each named for its unit and
	// account so a role is spelled one way everywhere.
	case "broker":
		return cmdBroker(args[1:])
	case "keeper":
		return cmdKeeper(args[1:])
	case "exec":
		return cmdExec(args[1:])
	case "mcp":
		return mcp.Run(args[1:])
	case "guard":
		return guard.Run(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "faramir: unknown command %q\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

// newFlagSet builds a subcommand's flag set with a usage line of its own.
func newFlagSet(name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "usage: faramir %s\n\noptions:\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags runs a subcommand's flag set.  --help is stdout and 0, a bad flag
// is stderr and 2; flag writes both through one handle, so the output is
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

// operatorName resolves the account that works in the tree: --operator, then
// SUDO_USER so `sudo faramir init` needs no flag, then the caller.
//
// root is not an answer at any position -- the tree belongs to somebody, and
// chowning a checkout to root would take it from its owner -- so escalating by
// another route means passing --operator.
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

// cmdKeygen mints an age keypair, so a faramir host needs no age binary.  It
// does not replace the sops CLI, which is what edits encrypted files.
func cmdKeygen(args []string) int {
	fs := newFlagSet("keygen", "keygen [-o FILE]")
	out := fs.String("o", "", "write the identity to this file instead of stdout")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	if *out == "" {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
			return 1
		}
		fmt.Print(agekey.Format(id))
		fmt.Fprintf(os.Stderr, "Public key: %s\n", id.Recipient())
		return 0
	}
	// Generate refuses to clobber: overwriting an age key destroys every sops
	// file it was the only recipient for, retroactively.
	recipient, created, err := agekey.Generate(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 1
	}
	// Non-zero on an existing target, so a caller can tell a fresh identity
	// from one that was already there.
	if !created {
		fmt.Fprintf(os.Stderr,
			"faramir: %s exists; refusing to overwrite an age key\n", *out)
		fmt.Fprintf(os.Stderr, "Public key: %s\n", recipient)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Public key: %s\n", recipient)
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
	// flag has stopped parsing by the time a leading "--" reaches us.
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "faramir run: no command given")
		fs.SetOutput(os.Stderr)
		fs.Usage()
		return 2
	}

	// Files first, so an explicit --env overrides the file.
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
	// The caller's own directory unless -C says otherwise: a brokered command
	// runs where it was typed.
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

// readEnvFile reads NAME=secret://ref lines, one per line, # for a comment.
// The file holds refs and never values, so it lives beside the playbook it
// belongs to; the request on the wire is the same either way.
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
		// Not last-wins: silently picking one of two is how the wrong
		// credential reaches a host.  An identical repeat is a merge artefact,
		// so it passes.
		if existing, seen := refs[name]; seen && existing != uri {
			return nil, fmt.Errorf("%s:%d: %s is given twice, as %s and %s",
				path, i+1, name, existing, uri)
		}
		refs[name] = uri
	}
	return refs, nil
}

// chunkBytes is how much text one redact request carries.  Well under the
// broker's default max_request_bytes, which applies to the JSON-encoded line:
// a control byte becomes six characters, so this cannot exceed it however badly
// it encodes.
const chunkBytes = 32 << 10

// cmdRedact scrubs text that did not come from a brokered command.  As a filter
// it reads stdin; given a command after --, it runs that command and filters
// what it prints, preserving its exit status.
func cmdRedact(args []string) int {
	fs := newFlagSet("redact", "redact [options] [-- command [args...]]")
	c := addCommon(fs)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if child := fs.Args(); len(child) > 0 {
		return redactChild(*c.socket, child)
	}
	unredacted, err := redactStream(*c.socket, os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
		return 1
	}
	// Non-zero when any of it went through untouched, so a caller that can
	// fail closed has something to act on.  The text is written either way: a
	// filter that swallowed its input would lose it for good.
	if unredacted {
		return 1
	}
	return 0
}

// redactChild runs the command with both its streams merged and filtered.
// Merged because the agent reads them as one transcript; separating them would
// reorder what it sees.  stdin is passed through.
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
	// The pass-through flag is dropped: the child's own status is what the
	// caller reads, and failing closed here would break the command rather than
	// the redaction.
	_, streamErr := redactStream(socketPath, output, os.Stdout)
	if streamErr != nil {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", streamErr)
		// Drain, or a child that fills the pipe blocks the Wait below.
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

// redactStream sends the input through the broker a chunk at a time, breaking
// on a newline where it can so a value is not split across two requests.  A
// multi-line value and a line longer than a chunk still split one.  ReadSlice
// rather than ReadBytes, which would grow one long line past
// max_request_bytes.
//
// A failed chunk is passed through unredacted and the next is still attempted,
// with the warning printed once.  Reports whether any chunk went through that
// way.
func redactStream(socketPath string, in io.Reader, out io.Writer) (bool, error) {
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
		// Flushed before the append: a partial buffer plus a full ReadSlice
		// would make one request of nearly twice chunkBytes.
		if len(buf) > 0 && len(buf)+len(line) > chunkBytes {
			if flushErr := flush(); flushErr != nil {
				return warned, flushErr
			}
		}
		buf = append(buf, line...)
		// A long line arrives in pieces; send what is there.
		if errors.Is(err, bufio.ErrBufferFull) {
			if flushErr := flush(); flushErr != nil {
				return warned, flushErr
			}
			continue
		}
		if len(buf) >= chunkBytes {
			if flushErr := flush(); flushErr != nil {
				return warned, flushErr
			}
		}
		if err != nil {
			if flushErr := flush(); flushErr != nil {
				return warned, flushErr
			}
			if errors.Is(err, io.EOF) {
				// flush reported it once already, and carries it back as the
				// flag rather than as an error.
				return warned, nil
			}
			return warned, err
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
		// Named, not flattened: an oversized request and a reset connection
		// want different fixes.
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
	// Only run has --quiet.
	return send(*c.socket, map[string]any{"op": op}, *c.json, true)
}

// send performs one request/response round trip.  Everything on this side of
// the socket has already been redacted.
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
		// Re-encoded for readability; a round trip through any changes
		// nothing.
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
		// Both change what the output means, so they are always reported.
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

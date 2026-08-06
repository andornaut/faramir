// Command faramir runs a credential-bearing command through the secret broker.
//
// Secrets are injected as environment variables only; they are never
// substituted into the command line.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"filippo.io/age"

	"github.com/andornaut/faramir/internal/sockutil"
)

const defaultSocket = "/run/faramir/broker.sock"

func main() { os.Exit(run(os.Args[1:])) }

func usage() {
	fmt.Fprint(os.Stderr, `usage: faramir [-h] <command> ...

Run a credential-bearing command through the secret broker.

positional arguments:
  <command>
    run           run a command with secrets injected
    list-secrets  list secret refs (names only)
    status        show broker status
    keygen        mint an age keypair for the keeper

options:
  -h, --help    show this help message and exit

Secrets are injected as environment variables only; they are never substituted
into the command line.
`)
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "list-secrets":
		return call("list_secrets", args[1:])
	case "status":
		return call("status", args[1:])
	case "keygen":
		return cmdKeygen(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "faramir: unknown command %q\n", args[0])
		usage()
		return 2
	}
}

// cmdKeygen mints an age keypair.
//
// This exists so a faramir host needs no age binary: the identity format is
// age's own, and the library that writes it is the one the keeper reads it
// with.  It does not replace the sops CLI, which is what an operator edits
// encrypted files with.
func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("o", "", "write the identity to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
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
	defer fh.Close()
	if _, err := fh.WriteString(body); err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Public key: %s\n", id.Recipient())
	return 0
}

// common registers the flags every subcommand shares.  --socket and --json are
// on all of them; the short forms exist because the CLI is typed by hand far
// more often than the MCP tools are.
type common struct {
	socket *string
	json   *bool
}

func addCommon(fs *flag.FlagSet) common {
	c := common{
		socket: fs.String("socket", defaultSocket, "broker socket path"),
		json:   fs.Bool("json", false, "print the raw response"),
	}
	return c
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	c := addCommon(fs)
	quiet := fs.Bool("quiet", false, "suppress the redaction summary")
	cwd := fs.String("cwd", "", "working directory for the command")
	fs.StringVar(cwd, "C", "", "working directory for the command (shorthand)")
	timeout := fs.Int("timeout", 0, "timeout in seconds")
	fs.IntVar(timeout, "t", 0, "timeout in seconds (shorthand)")
	var envRefs multiFlag
	fs.Var(&envRefs, "env", "NAME=secret://ref (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rest := fs.Args()
	// argparse's REMAINDER keeps a leading "--"; strip it so both spellings work.
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "faramir run: no command given")
		return 2
	}

	refs := map[string]string{}
	for _, pair := range envRefs {
		name, uri, ok := strings.Cut(pair, "=")
		if !ok {
			fmt.Fprintf(os.Stderr, "faramir run: --env expects NAME=secret://ref, got %q\n", pair)
			return 2
		}
		refs[name] = uri
	}

	request := map[string]any{"op": "exec", "cmd": rest}
	if len(refs) > 0 {
		request["env_refs"] = refs
	}
	if *cwd != "" {
		request["cwd"] = *cwd
	}
	if *timeout > 0 {
		request["timeout_sec"] = *timeout
	}
	return send(*c.socket, request, *c.json, *quiet)
}

// call runs a subcommand that takes no arguments of its own.
func call(op string, args []string) int {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	c := addCommon(fs)
	if err := fs.Parse(args); err != nil {
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
	defer conn.Close()

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
		// Re-encode rather than echoing the line, so the output is indented
		// like the Python CLI's and still exactly what the broker sent.
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

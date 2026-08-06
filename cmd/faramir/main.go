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
		return call(map[string]any{"op": "list_secrets"}, args[1:])
	case "status":
		return call(map[string]any{"op": "status"}, args[1:])
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

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	socket := fs.String("socket", defaultSocket, "broker socket path")
	cwd := fs.String("cwd", "", "working directory for the command")
	timeout := fs.Int("timeout", 0, "timeout in seconds")
	var envRefs multiFlag
	fs.Var(&envRefs, "env", "NAME=secret://ref (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "faramir run: no command; use -- before it")
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
	return send(*socket, request)
}

func call(request map[string]any, args []string) int {
	fs := flag.NewFlagSet("call", flag.ContinueOnError)
	socket := fs.String("socket", defaultSocket, "broker socket path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return send(*socket, request)
}

// send performs one request/response round trip.  No secret logic lives on
// this side of the socket: everything it can see has already been redacted.
func send(socketPath string, request map[string]any) int {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %s: %v\n", socketPath, err)
		return 1
	}
	defer conn.Close()

	if err := sockutil.Send(conn, request); err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %v\n", err)
		return 1
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<26)
	if err != nil || len(line) == 0 {
		fmt.Fprintln(os.Stderr, "faramir: broker closed the connection without responding")
		return 1
	}

	var response struct {
		ExitCode   *int   `json:"exit_code"`
		Output     string `json:"output"`
		Truncated  bool   `json:"truncated"`
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

	if response.Error != nil {
		fmt.Fprintf(os.Stderr, "faramir: %s: %s\n", response.Error.Code, response.Error.Message)
		if response.LogID != "" {
			fmt.Fprintf(os.Stderr, "[faramir] log_id=%s\n", response.LogID)
		}
		return 1
	}

	fmt.Print(response.Output)
	if len(response.Redactions) > 0 {
		var parts []string
		for _, r := range response.Redactions {
			parts = append(parts, fmt.Sprintf("%s×%d", r.Token, r.Count))
		}
		fmt.Fprintf(os.Stderr, "[faramir] redacted %s; log_id=%s\n",
			strings.Join(parts, ", "), response.LogID)
	}
	if response.ExitCode != nil {
		return *response.ExitCode
	}
	return 0
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

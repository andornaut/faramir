package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/brokerclient"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/secretref"
	"github.com/andornaut/faramir/internal/termui"
)

// brokerOptions is what every broker-facing subcommand shares.
type brokerOptions struct {
	json bool
}

func (o *brokerOptions) add(c *cobra.Command) {
	c.Flags().BoolVar(&o.json, "json", false, "print the raw response")
}

func newRunCmd() *cobra.Command {
	var (
		o        brokerOptions
		quiet    bool
		stdin    bool
		cwd      string
		timeout  string
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
		// The program's own flags are its own: with interspersing off (below)
		// pflag stops at the first non-flag word, the program name, so a `--quiet`
		// or `--env` after it is the program's and is passed through untouched.
		// A `--` still works and is not required.
		RunE: func(c *cobra.Command, rest []string) error {
			refs, err := secretref.EnvRefs(envFiles, envRefs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "faramir run: %v\n", err)
				return codeErr(2)
			}

			request := map[string]any{"op": brokerclient.OpRun, "cmd": rest}
			if len(refs) > 0 {
				request["env_refs"] = refs
			}
			// Resolved here rather than sent as it was typed: the broker runs the
			// command from its own directory, so a relative path means the
			// caller's directory or nothing. Printed here because an error
			// returned past this point is silenced.
			cwd, err = resolveCwd(cwd)
			if err != nil {
				fmt.Fprintf(os.Stderr, "faramir run: %v\n", err)
				return codeErr(2)
			}
			request["cwd"] = cwd
			// Printed here rather than returned as a usage error: past argument
			// validation the root command silences what a RunE returns, so a
			// usagef from here exits 2 and says nothing at all.
			seconds, err := durationSeconds("--timeout", timeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "faramir run: %v\n", err)
				return codeErr(2)
			}
			// Zero is "name none", which the broker reads as its configured
			// default.
			if seconds > 0 {
				request["timeout_sec"] = seconds
			}
			// Last, after every refusal that needs no input: reading stdin to its
			// end is the one step here that waits on something outside this
			// process, and a caller correcting a mistyped --cwd should not have
			// fed it a file first.
			//
			// Carried in the request rather than streamed after it: the broker
			// reads the connection for the whole of a run to know whether the
			// caller is still there, so bytes sent after the request are already
			// spoken for.
			piped, err := pipedStdin(stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "faramir run: %v\n", err)
				return codeErr(2)
			}
			if len(piped) > 0 {
				request["stdin"] = base64.StdEncoding.EncodeToString(piped)
			}
			if err := fitsOneRequest(request, len(piped)); err != nil {
				fmt.Fprintf(os.Stderr, "faramir run: %v\n", err)
				return codeErr(2)
			}
			return codeErr(send("run", socketDefault(), request, o.json, quiet))
		},
	}
	o.add(c)
	c.Flags().BoolVar(&quiet, "quiet", false, "suppress the redaction summary")
	c.Flags().BoolVarP(&stdin, "stdin", "i", false,
		"pass piped input to the command; without this flag, piped input is refused")
	c.Flags().StringVarP(&cwd, "cwd", "C", "", "working directory for the command (default: the current directory)")
	c.Flags().StringVarP(&timeout, "timeout", "t", "",
		"how long the command may run: a duration such as 90s or 5m, or a number of seconds")
	c.Flags().StringArrayVar(&envRefs, "env", nil,
		"NAME=faramir://ref, or NAME alone for the ref of the same name; repeatable")
	c.Flags().StringArrayVar(&envFiles, "env-file", nil,
		"file of NAME=faramir://ref lines, or NAME alone for the ref of the same name; repeatable")
	// Stop at the program name so its own flags stay with it. Without this pflag
	// reads a colliding flag after the command (-C, -t, --env, --quiet) as run's
	// own, running a different command than the caller typed.
	c.Flags().SetInterspersed(false)
	return c
}

// resolveCwd turns what -C was given into the absolute path the broker takes.
// The broker runs the command from a directory of its own, so a relative path
// there means nothing the caller named: it is resolved against the caller's
// directory here, which is also what an absent flag means, a brokered command
// running where it was typed.
//
// A directory that cannot be read is refused here rather than sent short. The
// broker has no default to fall back on and refuses a request naming no
// directory, so the round trip only moves the same refusal further from the
// caller, and this one can name the flag that answers it.
func resolveCwd(cwd string) (string, error) {
	if filepath.IsAbs(cwd) {
		return cwd, nil
	}
	here, err := os.Getwd()
	if err != nil {
		if cwd == "" {
			return "", fmt.Errorf(
				"the directory to run in cannot be read (%w); name one with -C", err)
		}
		return "", fmt.Errorf("--cwd %s cannot be resolved: %w", cwd, err)
	}
	if cwd == "" {
		return here, nil
	}
	return filepath.Join(here, cwd), nil
}

// pipedStdin is what the caller piped in, and only where they asked for it to
// be sent. Read whole rather than streamed, and refused past the cap rather
// than truncated: a command that read the first half of its input did something
// nobody asked for, and this exists because dropping the lot silently was
// worse.
//
// Behind a flag because this process does not own the file on its own standard
// input. `while read host; do faramir run ...; done < hosts.txt` hands every
// iteration the same open file, and a run that drained it would leave the loop
// with nothing to read; `ssh host 'faramir run ...'` without -n hands it a pipe
// from the local terminal, and a run that read to the end of that would wait
// for a person to press ctrl-D. Neither caller asked to send anything.
//
// A pipe with no flag is refused rather than ignored. Somebody who wrote
// `printf x | faramir run -- cat` meant the command to read it, and silence is
// the shape this whole thing exists to remove; a caller that wants the input
// dropped says so with a redirect from /dev/null.
func pipedStdin(asked bool) ([]byte, error) {
	if !asked {
		return nil, refusePipeWithoutTheFlag()
	}
	if termui.IsTerminal(os.Stdin) {
		return nil, nil
	}
	// One byte past the cap, so a file exactly at it is not reported as over.
	piped, err := io.ReadAll(io.LimitReader(os.Stdin, int64(config.MaxStdinBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	if len(piped) > config.MaxStdinBytes {
		return nil, fmt.Errorf("stdin is larger than the %d bytes a brokered "+
			"command takes: it travels inside one request. Write it to a file the "+
			"command opens itself", config.MaxStdinBytes)
	}
	return piped, nil
}

// refusePipeWithoutTheFlag is the error for a pipeline that named no -i, and
// nil for every other stdin. A FIFO alone: a terminal is a person who typed
// nothing, /dev/null is a caller saying so, and a regular file or an inherited
// socket is something this process does not own, none of which is a request to
// send anything.
//
// An anonymous pipe every writer has already closed with nothing in it is not
// one either, there being no input to send: that is what a child spawned with
// its standard input on a pipe holds once its parent has written what it had
// and closed the other end, which is how a configuration manager or any other
// program driving a subprocess hands one over. A FIFO is held to the rule
// above, no state of it being one a writer cannot return from.
func refusePipeWithoutTheFlag() error {
	// A stdin this process cannot ask about is not one to refuse a run over:
	// nothing here needs to read it, and the run goes ahead forwarding nothing,
	// as every run did before -i.
	info, err := os.Stdin.Stat()
	piped := err == nil && info.Mode()&os.ModeNamedPipe != 0
	if !piped || spentPipe() {
		return nil
	}
	return errors.New("something is piped in and -i was not given, so it would " +
		"reach nothing: pass -i to send it to the command, or redirect from " +
		"/dev/null to say it is not meant for one")
}

// spentPipe reports whether standard input is an anonymous pipe that will never
// deliver a byte: nothing is buffered and every writer has closed. Put to the
// kernel rather than answered by a read, so a pipe that does hold something
// still holds it for the command.
//
// POLLHUP is the closed writer and POLLIN the byte waiting, and the two are
// not exclusive: a pipe carrying data whose writer has gone reports both, and
// is an input somebody meant to send. Neither of them means a writer is still
// there and has yet to write, which is a pipeline as well.
func spentPipe() bool {
	fd := os.Stdin.Fd()
	if !anonymousPipe(fd) {
		return false
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		ready, err := unix.Poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || ready == 0 {
			return false
		}
		return fds[0].Revents&unix.POLLHUP != 0 && fds[0].Revents&unix.POLLIN == 0
	}
}

// anonymousPipe reports whether standard input is a pipe with no name. A FIFO
// is S_IFIFO too and hangs up the same way, and is not the same thing: another
// writer may open one after the last has closed, so a hangup there says nothing
// has arrived yet rather than that nothing can, and letting it through would
// drop what that writer sends. Only an anonymous pipe is in a state no writer
// can return from, its last end having gone with the name.
//
// /proc is what separates them: an anonymous pipe reads back as `pipe:[inode]`
// and a FIFO as its own path. A link that cannot be read leaves the pipe
// refused, which is the answer every one of them got before a spent one was
// let through.
func anonymousPipe(fd uintptr) bool {
	link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	return err == nil && strings.HasPrefix(link, "pipe:[")
}

// fitsOneRequest refuses a request the broker's socket would cut off. The
// stdin cap leaves room for an ordinary command beside it, and a long one plus
// a maximal input still overruns: the broker answers that with the size of the
// line, which names neither half. Said here, where both halves are in hand.
func fitsOneRequest(request map[string]any, piped int) error {
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(encoded) <= config.MaxRequestBytes {
		return nil
	}
	if piped > 0 {
		return fmt.Errorf("the command and its %d bytes of input come to %d, and a "+
			"request is at most %d: shorten the command, or write the input to a "+
			"file the command opens itself", piped, len(encoded), config.MaxRequestBytes)
	}
	return fmt.Errorf("the command comes to %d bytes and a request is at most %d",
		len(encoded), config.MaxRequestBytes)
}

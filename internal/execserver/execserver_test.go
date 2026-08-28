package execserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/ptyutil"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

func newExecutor(t *testing.T) (*Executor, string, string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "exec.sock")
	cfg := &config.Config{
		Command: config.CommandConfig{
			TimeoutSec: 15},
		Executor: config.ExecutorConfig{SocketPath: sock},
	}
	e := New(cfg)
	// Confinement is mandatory: an executor with no delegated cgroup refuses every
	// command, so a test that runs one has nothing to assert on such a host. CI
	// delegates a cgroup to the runner and exercises the real path; a workstation
	// whose shell sits in a root-owned cgroup skips instead of failing. Run under
	// `systemd-run --user --scope go test ./...` to get a delegated cgroup locally.
	if e.cgroupBase == "" {
		t.Skip("no delegated cgroup on this host; the executor refuses every command here")
	}
	if _, err := e.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = e.Serve() }()
	t.Cleanup(func() { _ = e.Close() })
	return e, sock, dir
}

// runChild runs one command the way the broker would, draining the PTY as it
// goes: waiting for the status first deadlocks on a full terminal buffer.
func runChild(t *testing.T, sock string, argv []string, cwd string) (*ChildResult, string, error) {
	t.Helper()
	master, slave, err := ptyutil.Open()
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(sock)
	startErr := client.Start(argv, cwd, map[string]string{"PATH": "/usr/bin:/bin"}, "", 5, 2, slave.Fd())
	_ = slave.Close()
	if startErr != nil {
		_ = master.Close()
		return nil, "", startErr
	}

	var wg sync.WaitGroup
	var output strings.Builder
	wg.Go(func() {
		// One deadline for the whole drain; resetting it inside the loop races with
		// the close below.
		_ = master.SetReadDeadline(time.Now().Add(30 * time.Second))
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				output.Write(buf[:n])
			}
			if err != nil {
				return // EIO is the normal EOF on a PTY
			}
		}
	})

	result, err := client.Result(20 * time.Second)
	// Drain to EOF first: the child's last write can still be in the terminal
	// buffer when the result arrives. Every slave fd is closed by then, so the
	// read ends in EIO.
	wg.Wait()
	_ = master.Close()
	return result, output.String(), err
}

// TestTheExecutorDoesNotSecondGuessArgv0 pins the absence of a check: the
// executor runs what the broker sends, from wherever the broker says. What
// bounds this uid is what it holds (no key, no audit log, no SSH key) plus the
// mode on its socket.
func TestTheExecutorDoesNotSecondGuessArgv0(t *testing.T) {
	_, sock, dir := newExecutor(t)

	script := filepath.Join(dir, "anywhere.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho RAN_FROM_TMP\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, output, err := runChild(t, sock, []string{script}, dir)
	if err != nil {
		t.Fatalf("the executor refused a program outside the system directories: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit = %d, output = %q", result.ExitCode, output)
	}
	if !strings.Contains(output, "RAN_FROM_TMP") {
		t.Errorf("output = %q", output)
	}
}

// stdin is /dev/null, so a bare interactive shell exits rather than holding a
// concurrency slot until its timeout.
func TestABareShellExitsInsteadOfWaiting(t *testing.T) {
	_, sock, dir := newExecutor(t)
	if info, err := os.Stat("/bin/bash"); err != nil || info.IsDir() {
		t.Skip("no /bin/bash")
	}
	result, _, err := runChild(t, sock, []string{"/bin/bash"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.TimedOut {
		t.Error("a bare shell waited for stdin")
	}
	if result.ExitCode != 0 {
		t.Errorf("exit = %d", result.ExitCode)
	}
}

// The child owns a terminal, so progress meters and /dev/tty writes land on the
// broker's master.
func TestTheChildGetsATerminal(t *testing.T) {
	_, sock, dir := newExecutor(t)
	_, output, err := runChild(t, sock,
		[]string{shPath(t), "-c", "test -t 1 && echo IS_TTY || echo NOT_TTY"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "IS_TTY") {
		t.Errorf("output = %q", output)
	}
}

func TestAMissingProgramIsExecFailed(t *testing.T) {
	_, sock, dir := newExecutor(t)
	_, _, err := runChild(t, sock, []string{filepath.Join(dir, "nope")}, dir)
	if err == nil {
		t.Fatal("a missing program was accepted")
	}
	if !strings.Contains(err.Error(), "exec_failed") {
		t.Errorf("err = %v", err)
	}
}

// The claim the cgroup exists for: a child that calls setsid, breaking out of
// the process group a killpg would reach, is still reaped when the run ends,
// because it cannot leave the run's cgroup. The command detaches a grandchild
// that would outlive it, prints the grandchild's pid, and exits; once the run is
// done the grandchild must be gone.
func TestASetsidChildIsReapedWithTheRun(t *testing.T) {
	_, sock, dir := newExecutor(t)
	sh := shPath(t)

	// setsid detaches the grandchild into its own session and process group; it
	// prints its pid and sleeps. The main shell exits at once.
	//
	// The sleep outlasts every bound in the teardown by a wide margin, and that
	// is what makes this an assertion. Teardown waits for the cgroup to drain,
	// so with a sleep it can outlast, "dead once the run returned" is satisfied
	// by the sleep finishing on its own, and the test passes with the reaping
	// disabled entirely. Longer than any drain, only something killing it can
	// satisfy it.
	_, output, err := runChild(t, sock, []string{sh, "-c",
		"setsid sh -c 'echo GPID=$$; exec sleep 600' & sleep 0.3"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var gpid int
	for field := range strings.FieldsSeq(output) {
		if after, ok := strings.CutPrefix(field, "GPID="); ok {
			gpid, _ = strconv.Atoi(strings.TrimSpace(after))
		}
	}
	if gpid <= 0 {
		t.Fatalf("no grandchild pid in output %q", output)
	}
	// The run has returned, so rcg.close() has already killed and drained the
	// cgroup. A process-group kill would have missed this pid; the cgroup did not.
	// "Running" excludes a zombie: a killed process the reaper has not collected is
	// dead, holds nothing, and satisfies the claim, and kill(pid, 0) would call it
	// alive, so the state is read instead.
	//
	// Waited for rather than read once. close() bounds its own drain, so on a
	// loaded host the last exit can land just after that wait gives up, and what
	// is being asserted is that the cgroup reaps this pid rather than how many
	// milliseconds the kernel took. The grandchild sleeps for a minute, so a
	// bound of seconds still separates a cgroup that reaped it from a
	// process-group kill that never reached it.
	if !diesWithin(gpid, 15*time.Second) {
		t.Errorf("setsid grandchild %d is still running after the run: the cgroup did "+
			"not reap it", gpid)
	}
}

// diesWithin waits for a pid to stop running, up to a bound.
func diesWithin(pid int, bound time.Duration) bool {
	deadline := time.Now().Add(bound)
	for {
		if !running(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// running reports whether a pid is a live process, a zombie counting as dead: it
// has been killed and holds nothing, only awaiting a reap. Missing is dead too.
func running(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// The state is the field after the comm, which is parenthesised and may itself
	// hold spaces or ')', so the scan starts past the last ')'.
	end := bytes.LastIndexByte(data, ')')
	fields := strings.Fields(string(data)[end+1:])
	return len(fields) > 0 && fields[0] != "Z"
}

// Confinement is mandatory for every run, a sudo grant or not: with no usable
// cgroup the executor refuses to run rather than reap by process group, which a
// setsid child escapes. There is no fallback, so this holds on any host. Forced
// by clearing the discovered base, so the refusal is exercised even where a
// cgroup is in fact available.
func TestAnExecutorWithoutACgroupRefusesEveryCommand(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "exec.sock")
	e := New(&config.Config{
		Command:  config.CommandConfig{TimeoutSec: 15},
		Executor: config.ExecutorConfig{SocketPath: sock},
	})
	e.cgroupBase = "" // as on a host without cgroup v2, Delegate=, or cgroup.kill
	if _, err := e.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = e.Serve() }()
	t.Cleanup(func() { _ = e.Close() })

	if _, _, err := runChild(t, sock, []string{"/bin/sh", "-c", "true"}, dir); err == nil ||
		!strings.Contains(err.Error(), "cgroup") {
		t.Errorf("err = %v, want a refusal naming the missing cgroup", err)
	}
}

// The three daemons are one binary under three units, so an executor answering
// a broker of another release is one of them left running across the install
// that replaced it. Blocked before the op and before the terminal fd, since
// what changed under it may be either.
func TestARequestOfAnotherReleaseIsRefused(t *testing.T) {
	_, sock, _ := newExecutor(t)
	for _, probe := range []struct{ name, caller string }{
		{"an older release", "0.1.4"},
		{"none, which is what a client built before the field sends", ""},
	} {
		t.Run(probe.name, func(t *testing.T) {
			conn, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			// opQuiescent carries no PTY, so a refusal here is the version check and
			// not the missing fd.
			if err := sockutil.Send(conn, request{
				Op: opQuiescent, Version: probe.caller}); err != nil {
				t.Fatal(err)
			}
			line, err := sockutil.ReadLine(conn, maxRequestBytes)
			if err != nil {
				t.Fatal(err)
			}
			var response struct {
				Quiescent bool `json:"quiescent"`
				Error     *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(line, &response); err != nil {
				t.Fatal(err)
			}
			if response.Error == nil {
				t.Fatalf("not refused: %s", line)
			}
			if response.Error.Code != "bad_request" {
				t.Errorf("code = %q, want bad_request", response.Error.Code)
			}
			if !strings.Contains(response.Error.Message, version.Version) {
				t.Errorf("the refusal does not name this release: %s", response.Error.Message)
			}
		})
	}
}

// The kernel refuses the exec for two different reasons with one EACCES, and
// the sentence added here says which. The probe has to ask the permission the
// exec needs: entering a directory takes x, opening it takes r, and a 0710
// home -- which is what sharing a tree leaves behind -- has x for the group and
// not r. Asked as a read, every unrunnable program in such a tree was blamed on
// the tree, and the operator was sent to run `init-project` on one that was
// already right.
func TestStartFailureBlamesTheProgramWhenTheDirectoryIsOnlyTraversable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root enters and reads whatever the mode says")
	}
	dir := t.TempDir()
	program := filepath.Join(dir, "prog")
	if err := os.WriteFile(program, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Traversable and not readable, which is the shape a shared tree leaves.
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	code, got := startFailure(program, dir, os.ErrPermission)
	if code != codeNotExecutable {
		t.Errorf("code = %q, want %q: a program the kernel would not run is the "+
			"shell's 126", code, codeNotExecutable)
	}
	if !strings.Contains(got, "may not execute") {
		t.Errorf("startFailure = %q, want it to blame the program", got)
	}
	if strings.Contains(got, "cannot enter") {
		t.Errorf("startFailure = %q, which sends the operator to a tree that is fine", got)
	}

	// And a directory that genuinely cannot be entered is still named.
	closed := filepath.Join(t.TempDir(), "shut")
	if err := os.Mkdir(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	code, got = startFailure(program, closed, os.ErrPermission)
	if !strings.Contains(got, "cannot enter") {
		t.Errorf("startFailure = %q, want it to name the directory", got)
	}
	// Not 126: the program may be perfectly runnable, and what failed is
	// getting to where it was to run.
	if code != codeExecFailed {
		t.Errorf("code = %q, want %q for a directory that cannot be entered",
			code, codeExecFailed)
	}
}

// A StartError renders "code: detail" so the broker's splitExecCode reads its
// code, and errors.As classifies it apart from a transport fault: a reported
// start failure must not be mistaken for a lost status.
func TestStartErrorCarriesItsCode(t *testing.T) {
	err := error(&StartError{Code: "not_executable", Detail: "x may not execute y"})
	if got, want := err.Error(), "not_executable: x may not execute y"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	var se *StartError
	if !errors.As(err, &se) {
		t.Fatal("errors.As did not recognise a StartError")
	}
	if se.Code != "not_executable" {
		t.Errorf("Code = %q, want not_executable", se.Code)
	}
}

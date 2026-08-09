package execserver

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/ptyutil"
)

func newExecutor(t *testing.T) (*Executor, string, string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "exec.sock")
	cfg := &config.Config{
		Exec: config.ExecConfig{
			DefaultTimeoutSec: 15, KillGraceSec: 2,
			TermCols: 120, TermRows: 40,
		},
		Executor: config.ExecutorConfig{SocketPath: sock, SocketMode: 0o600},
	}
	e := New(cfg)
	if _, err := e.Listen(); err != nil {
		t.Fatal(err)
	}
	go e.Serve()
	t.Cleanup(func() { e.Close() })
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
	startErr := client.Start(argv, cwd, map[string]string{"PATH": "/usr/bin:/bin"}, 5, 2, slave.Fd())
	_ = slave.Close()
	if startErr != nil {
		_ = master.Close()
		return nil, "", startErr
	}

	var wg sync.WaitGroup
	var output strings.Builder
	wg.Add(1)
	go func() {
		defer wg.Done()
		// One deadline for the whole drain; resetting it inside the loop races
		// with the close below.
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
	}()

	result, err := client.Result(20 * time.Second)
	// Drain to EOF first: the child's last write can still be in the terminal
	// buffer when the result arrives.  Every slave fd is closed by then, so the
	// read ends in EIO.
	wg.Wait()
	_ = master.Close()
	return result, output.String(), err
}

// TestTheExecutorDoesNotSecondGuessArgv0 pins the absence of a check: the
// executor runs what the broker sends, from wherever the broker says.  What
// bounds this uid is what it holds -- no key, no audit log, no SSH key -- plus
// the mode on its socket.
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
	sh, err := os.Stat("/bin/bash")
	if err != nil || sh.IsDir() {
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
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	_, output, err := runChild(t, sock,
		[]string{"/bin/sh", "-c", "test -t 1 && echo IS_TTY || echo NOT_TTY"}, dir)
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

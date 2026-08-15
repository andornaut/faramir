package execserver

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/ptyutil"
)

func shPath(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/bin/sh", "/usr/bin/sh"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no /bin/sh")
	return ""
}

// startChild sends a request and returns the client without collecting the
// result, so the test can hang up mid-command.
func startChild(t *testing.T, sock string, argv []string, cwd string, timeoutSec int) (*Client, *os.File) {
	t.Helper()
	master, slave, err := ptyutil.Open()
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(sock)
	err = client.Start(argv, cwd, map[string]string{"PATH": "/usr/bin:/bin"}, timeoutSec, 1, slave.Fd())
	_ = slave.Close()
	if err != nil {
		_ = master.Close()
		t.Fatal(err)
	}
	// Drain, or the child blocks once it fills the terminal buffer.
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = master.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := master.Read(buf); err != nil {
				return
			}
		}
	}()
	return client, master
}

func waitForFile(t *testing.T, path string, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			return strings.TrimSpace(string(data))
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
	return ""
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// Closing the connection means "give up": no orphan holding a credential in its
// environment survives the broker dying mid-command.
func TestAChildIsKilledWhenTheBrokerHangsUp(t *testing.T) {
	_, sock, dir := newExecutor(t)
	sh := shPath(t)
	pidFile := filepath.Join(dir, "pid")

	client, master := startChild(t, sock, []string{sh, "-c", "echo $$ > " + pidFile + "; sleep 60"}, dir, 120)
	defer func() { _ = master.Close() }()

	pid, err := strconv.Atoi(waitForFile(t, pidFile, 10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !alive(pid) {
		t.Fatal("the child was not running")
	}

	client.Abort() // hang up

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pid %d survived the broker hanging up", pid)
}

// The executor owns the timeout, because it owns the run's cgroup.
func TestTimeoutIsEnforcedByTheExecutor(t *testing.T) {
	_, sock, dir := newExecutor(t)
	sh := shPath(t)

	started := time.Now()
	result, _, err := runChild(t, sock, []string{sh, "-c", "sleep 60"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut {
		t.Error("timed_out was not reported")
	}
	if elapsed := time.Since(started); elapsed > 30*time.Second {
		t.Errorf("took %v; the timeout did not fire", elapsed)
	}
}

func TestExitCodesSurviveTheExtraHop(t *testing.T) {
	_, sock, dir := newExecutor(t)
	sh := shPath(t)
	for _, want := range []int{0, 1, 42} {
		result, _, err := runChild(t, sock, []string{sh, "-c", "exit " + strconv.Itoa(want)}, dir)
		if err != nil {
			t.Fatalf("exit %d: %v", want, err)
		}
		if result.ExitCode != want {
			t.Errorf("exit_code = %d, want %d", result.ExitCode, want)
		}
	}
}

// A signalled child reports 128+signal, the way a shell does.
func TestAKilledChildReportsASignalExitCode(t *testing.T) {
	_, sock, dir := newExecutor(t)
	sh := shPath(t)
	result, _, err := runChild(t, sock, []string{sh, "-c", "kill -TERM $$; sleep 5"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 128+int(syscall.SIGTERM) {
		t.Errorf("exit_code = %d, want %d", result.ExitCode, 128+int(syscall.SIGTERM))
	}
}

// -- separation -------------------------------------------------------------

// HOME belongs to the executor's uid; ansible creates ~/.ansible/tmp
// unconditionally.
func TestTheChildHomeIsNotTheBrokers(t *testing.T) {
	_, sock, dir := newExecutor(t)
	sh := shPath(t)
	_, output, err := runChild(t, sock, []string{sh, "-c", "echo HOME=$HOME"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "HOME=") {
		t.Fatalf("output = %q", output)
	}
	if strings.Contains(output, "HOME=\r\n") || strings.Contains(output, "HOME=\n") {
		t.Errorf("HOME was empty: %q", output)
	}
}

// Exactly what the broker sent plus HOME: inheriting would hand the child
// whatever the broker holds.
func TestTheChildDoesNotInheritTheBrokersEnvironment(t *testing.T) {
	_, sock, dir := newExecutor(t)
	sh := shPath(t)
	t.Setenv("FARAMIR_LEAK_CANARY", "must-not-appear")

	_, output, err := runChild(t, sock, []string{sh, "-c", "echo CANARY=[$FARAMIR_LEAK_CANARY]"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "CANARY=[]") {
		t.Errorf("the broker's environment leaked into the child: %q", output)
	}
}

// The child gets no controlling terminal, so /dev/tty cannot be opened at all.
// That is what keeps a prompt from blocking: ssh and sudo read /dev/tty so a
// pipe cannot answer them, and nothing writes to the master, so the read would
// last until the timeout.
func TestTheChildHasNoControllingTerminal(t *testing.T) {
	_, sock, dir := newExecutor(t)
	sh := shPath(t)
	_, output, err := runChild(t, sock,
		[]string{sh, "-c", "echo TO_TTY > /dev/tty 2>/dev/null || echo NO_TTY"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "NO_TTY") {
		t.Errorf("/dev/tty was writable, so a prompt read from it would block: %q", output)
	}
}

// And a read of it ends rather than waiting out the timeout, which is the whole
// point of having no controlling terminal.
func TestAReadOfDevTtyEndsAtOnce(t *testing.T) {
	_, sock, dir := newExecutor(t)
	sh := shPath(t)
	done := make(chan string, 1)
	go func() {
		_, output, err := runChild(t, sock,
			[]string{sh, "-c", "head -1 /dev/tty 2>/dev/null; echo ENDED"}, dir)
		if err != nil {
			done <- "error: " + err.Error()
			return
		}
		done <- output
	}()
	select {
	case output := <-done:
		if !strings.Contains(output, "ENDED") {
			t.Errorf("the command did not run to the end: %q", output)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a read of /dev/tty blocked, so a prompt holds its slot until the timeout")
	}
}

// stdout and stderr are still the PTY, so a program that falls back to them
// when /dev/tty will not open is captured as before.  This is what an operator
// still sees of a prompt.
func TestStderrIsStillCaptured(t *testing.T) {
	_, sock, dir := newExecutor(t)
	sh := shPath(t)
	_, output, err := runChild(t, sock,
		[]string{sh, "-c", "echo TO_STDERR >&2"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "TO_STDERR") {
		t.Errorf("stderr was not captured: %q", output)
	}
}

// -- client errors ----------------------------------------------------------

func TestAMissingSocketIsAClearError(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "absent.sock"))
	master, slave, err := ptyutil.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = master.Close() }()
	err = client.Start([]string{"/bin/true"}, "/tmp", nil, 5, 1, slave.Fd())
	_ = slave.Close()
	if err == nil {
		t.Fatal("connecting to a missing socket succeeded")
	}
	if !strings.Contains(err.Error(), "executor socket") {
		t.Errorf("message = %q", err.Error())
	}
}

func TestResultWithoutACommandInFlight(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "absent.sock"))
	if _, err := client.Result(time.Second); err == nil {
		t.Fatal("Result succeeded with nothing in flight")
	}
}

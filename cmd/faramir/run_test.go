package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run's flags stop at the program name, so a colliding flag after it is the
// program's and is passed through, with or without a "--".
func TestRunDoesNotStealTheChildsFlags(t *testing.T) {
	c := newRunCmd()
	args := []string{"deploy.sh", "--quiet", "--env", "production", "-C", "/elsewhere"}
	if err := c.Flags().Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := strings.Join(c.Flags().Args(), " "); got != strings.Join(args, " ") {
		t.Errorf("run consumed the child's flags: rest = %q, want %q", got, strings.Join(args, " "))
	}
	if q, _ := c.Flags().GetBool("quiet"); q {
		t.Error("the child's --quiet was read as run's own")
	}
	if env, _ := c.Flags().GetStringArray("env"); len(env) != 0 {
		t.Errorf("the child's --env was read as run's own: %v", env)
	}
}

// run's own flags before the program name still parse, and the program name and
// everything after it are the child's.
func TestRunReadsItsOwnFlagsBeforeTheCommand(t *testing.T) {
	c := newRunCmd()
	if err := c.Flags().Parse([]string{"-C", "/work", "--quiet", "deploy.sh", "--env", "production"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if q, _ := c.Flags().GetBool("quiet"); !q {
		t.Error("run's own --quiet before the command was not read")
	}
	if cwd, _ := c.Flags().GetString("cwd"); cwd != "/work" {
		t.Errorf("cwd = %q, want /work", cwd)
	}
	if got := strings.Join(c.Flags().Args(), " "); got != "deploy.sh --env production" {
		t.Errorf("child args = %q, want %q", got, "deploy.sh --env production")
	}
}

// A refusal raised before the broker is contacted goes to the real os.Stderr.
// Past PersistentPreRunE the root command silences what a RunE returns, so a
// message written to cobra's own writer or returned as a usage error arrives
// nowhere and the caller is given a silent exit 2. The fd is captured rather
// than cobra's writer for that reason: the mistake this catches is the one that
// looks right in a test using SetErr.
func TestAPreBrokerRefusalReachesTheRealStderr(t *testing.T) {
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	root := newRootCmd()
	root.SetArgs([]string{"run", "-t", "nonsense", "--", "echo", "hi"})
	code := exitCode(root.Execute())
	_ = w.Close()
	os.Stderr = old
	msg, _ := io.ReadAll(r)

	if code != 2 {
		t.Errorf("exit = %d, want 2 for an unparseable --timeout", code)
	}
	if !strings.Contains(string(msg), "--timeout") {
		t.Errorf("stderr = %q, want it to name the flag the caller has to retype", msg)
	}
}

// A working directory deleted from under the process is refused here rather
// than sent short: the broker has no default, so a request naming no directory
// comes back refused a round trip later saying less.
func TestACallerWithNoDirectoryIsRefusedBeforeTheBroker(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "gone")
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	_, err := resolveCwd("")
	if err == nil {
		t.Fatal("a deleted working directory was accepted, leaving the broker to refuse it")
	}
	if !strings.Contains(err.Error(), "-C") {
		t.Errorf("the refusal is %q, and names no flag, so a caller reading it "+
			"does not know what answers it", err)
	}
}

// A relative -C is the caller's directory plus that path, never the broker's:
// the broker runs from a directory of its own, so an unresolved relative path
// is the one place a caller could name a directory and be given another.
func TestARelativeCwdResolvesAgainstTheCaller(t *testing.T) {
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cwd  string
		want string
	}{
		{name: "absolute is untouched", cwd: "/work", want: "/work"},
		{name: "empty is the caller's own", cwd: "", want: here},
		{name: "dot is the caller's own", cwd: ".", want: here},
		{name: "relative hangs off it", cwd: "relative/dir",
			want: filepath.Join(here, "relative/dir")},
		// Cleaned on the way, because the broker compares what it is given
		// against a real directory and a dotted spelling of one is a spelling.
		{name: "a dotted spelling is cleaned", cwd: "sub/../other",
			want: filepath.Join(here, "other")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveCwd(tc.cwd)
			if err != nil {
				t.Fatalf("resolveCwd(%q): %v", tc.cwd, err)
			}
			if got != tc.want {
				t.Errorf("resolveCwd(%q) = %q, want %q", tc.cwd, got, tc.want)
			}
		})
	}
}

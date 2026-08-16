package resolve

// Turning cmd[0] into the path the executor runs.  There is no allowlist; what
// matters is resolving a name to the file the child would itself have run, since
// getting it wrong runs a different file.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

func cfgWithPath(path string) config.ExecConfig {
	return config.ExecConfig{BaseEnv: map[string]string{"PATH": path}}
}

// fixture holds an executable script, a plain file and a symlink to the script:
// every shape Program tells apart.
func fixture(t *testing.T) (dir, script string) {
	t.Helper()
	dir = t.TempDir()
	script = filepath.Join(dir, "deploy.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(script, filepath.Join(dir, "link.sh")); err != nil {
		t.Fatal(err)
	}
	return dir, script
}

func TestProgram(t *testing.T) {
	dir, script := fixture(t)

	for _, tc := range []struct {
		name  string
		arg   string
		cwd   string
		cfg   config.ExecConfig
		want  string   // the resolved path; "" means the call must fail
		wants []string // substrings the failure has to carry
		why   string
	}{
		// -- bare names: looked up on the PATH the child will actually get ---
		{name: "a bare name resolves on the configured PATH",
			arg: "sh", cwd: "/", cfg: cfgWithPath("/usr/bin:/bin"), want: realpath("/bin/sh")},
		{name: "the broker's own PATH is not consulted",
			arg: "sh", cwd: "/", cfg: cfgWithPath("/nonexistent"),
			wants: []string{"not found on the broker's PATH"},
			why:   "the process PATH almost certainly has /bin; base_env does not"},
		{name: "the error says where to put a venv",
			arg: "ansible-playbook", cwd: "/", cfg: cfgWithPath("/nonexistent"),
			wants: []string{"base_env", "venv"},
			why:   "the one failure an operator will hit, so it has to be self-correcting"},

		// -- PATH components that are not absolute ---------------------------
		// A shell reads these as its working directory.  The broker's is not the
		// child's, so honouring one would test a file the executor is not going to
		// run, and return a relative path from a function that promises absolute.
		{name: "a leading empty PATH component is skipped",
			arg: "sh", cwd: "/", cfg: cfgWithPath(":/bin"), want: realpath("/bin/sh")},
		{name: "a trailing empty PATH component is skipped",
			arg: "sh", cwd: "/", cfg: cfgWithPath("/bin:"), want: realpath("/bin/sh")},
		{name: "an empty PATH finds nothing",
			arg: "sh", cwd: "/", cfg: cfgWithPath(""),
			wants: []string{"not found on the broker's PATH"}},
		{name: "a PATH of nothing but empty components finds nothing",
			arg: "sh", cwd: "/", cfg: cfgWithPath("::"),
			wants: []string{"not found on the broker's PATH"}},
		{name: "a relative PATH component is skipped",
			arg: "deploy.sh", cwd: dir, cfg: cfgWithPath("."),
			wants: []string{"not found on the broker's PATH"},
			why:   "resolved against the broker's cwd, never the request's"},

		// -- explicit paths --------------------------------------------------
		{name: "an absolute path anywhere is fine",
			arg: script, cwd: dir, want: realpath(script),
			why: "no allowed_bin_dirs any more: a script in the working tree never lived in /usr/bin"},
		{name: "a relative path resolves against the request cwd",
			arg: "./deploy.sh", cwd: dir, want: realpath(script),
			why: "not the broker's own cwd, which would be a different file of the same name"},
		{name: "a different cwd does not find it",
			arg: "./deploy.sh", cwd: "/usr"},
		{name: "a symlink resolves to its target",
			arg: filepath.Join(dir, "link.sh"), cwd: dir, want: realpath(script)},
		{name: "an absolute path ignores the cwd",
			arg: "/bin/sh", cwd: "/tmp", want: realpath("/bin/sh"),
			why: "filepath.Join would produce /tmp/bin/sh; the child's own exec would not"},
		{name: "a missing program is named",
			arg: filepath.Join(dir, "nope"), cwd: dir, wants: []string{"no such program"}},
		// The executor's uid can hold permissions the broker does not, so the
		// bit is not read here: its own EACCES is the honest answer.
		{name: "a non-executable file is left to the executor",
			arg: filepath.Join(dir, "notes.txt"), cwd: dir,
			want: realpath(filepath.Join(dir, "notes.txt"))},
		{name: "an empty command is refused", arg: "", cwd: dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Program(tc.arg, tc.cwd, tc.cfg)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("resolved to %q, want a failure: %s", got, tc.why)
				}
				for _, want := range tc.wants {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("message does not mention %q: %q", want, err.Error())
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("%v: %s", err, tc.why)
			}
			if got != tc.want {
				t.Errorf("Program(%q) = %q, want %q", tc.arg, got, tc.want)
			}
		})
	}
}

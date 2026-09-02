package broker

// Turning cmd[0] into the path the executor runs. There is no allowlist; what
// matters is resolving a name to the file the child would itself have run, since
// getting it wrong runs a different file.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

func cfgWithPath(path string) config.CommandConfig {
	return config.CommandConfig{Env: map[string]string{"PATH": path}}
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

func TestProgramResolvesAgainstTheChildsOwnPath(t *testing.T) {
	dir, script := fixture(t)

	for _, tc := range []struct {
		name     string
		arg      string
		cwd      string
		cfg      config.CommandConfig
		want     string   // the resolved path; "" means the call must fail
		wants    []string // substrings the failure has to carry
		unwanted []string // substrings it must not
		why      string
	}{
		// -- bare names: looked up on the PATH the child will actually get ---
		{name: "a bare name resolves on the configured PATH",
			arg: "sh", cwd: "/", cfg: cfgWithPath("/usr/bin:/bin"), want: realpath("/bin/sh")},
		{name: "the broker's own PATH is not consulted",
			arg: "sh", cwd: "/", cfg: cfgWithPath("/nonexistent"),
			wants: []string{"not found on the broker's PATH"},
			why:   "the process PATH almost certainly has /bin; env does not"},
		{name: "the error says where to put a venv",
			arg: "ansible-playbook", cwd: "/", cfg: cfgWithPath("/nonexistent"),
			wants: []string{"env", "venv"},
			why:   "the one failure an operator will hit, so it has to be self-correcting"},

		// -- PATH components that are not absolute ---------------------------
		// A shell reads these as its working directory. The broker's is not the
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
			why: "there is no allowlist: a script in the working tree never lived in /usr/bin"},
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
		// Named once: resolving an absolute path that is nowhere changes nothing,
		// so saying what it resolved to repeats what was typed.
		{name: "a missing program is named",
			arg: filepath.Join(dir, "nope"), cwd: dir,
			wants: []string{"no such program"}, unwanted: []string{"resolved to"}},
		{name: "and a relative one says where it looked",
			arg: "./nope", cwd: dir, wants: []string{"no such program", "resolved to"}},
		// Told apart from the one above. A path the caller can see, called "no
		// such program", reads as a typo in the path rather than as a path that
		// holds no program.
		{name: "a directory is not a missing program",
			arg: dir, cwd: dir, wants: []string{"not a program", "directory"}},
		{name: "nor is a device",
			arg: "/dev/null", cwd: dir, wants: []string{"not a program", "device"}},
		// The executor's uid can hold permissions the broker does not, so the
		// bit is not read here: its own EACCES is the honest answer.
		{name: "a non-executable file is left to the executor",
			arg: filepath.Join(dir, "notes.txt"), cwd: dir,
			want: realpath(filepath.Join(dir, "notes.txt"))},
		{name: "an empty command is refused", arg: "", cwd: dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveProgram(tc.arg, tc.cwd, tc.cfg)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("resolved to %q, want a failure: %s", got, tc.why)
				}
				for _, unwanted := range tc.unwanted {
					if strings.Contains(err.Error(), unwanted) {
						t.Errorf("the message carries %q: %v", unwanted, err)
					}
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
				t.Errorf("resolveProgram(%q) = %q, want %q", tc.arg, got, tc.want)
			}
		})
	}
}

// A bare name that is on the PATH and carries no execute bit. It was answered
// "not found on the broker's PATH ... a venv, pipx, a version-manager shim",
// which sends an operator to install a program that is already installed, and
// exits 127 where a shell exits 126.
//
// Told apart from a program only the executor can run: the broker reads the
// execute bit as itself, so a file executable by another uid is reported as
// not found, and an absolute path in cmd[0] is the way past that. Only a file
// no account can run is named here.
func TestAProgramOnThePathWithNoExecuteBitIsNotReportedAsMissing(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "deploy")
	if err := os.WriteFile(program, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.CommandConfig{Env: map[string]string{"PATH": dir}}

	_, err := resolveProgram("deploy", dir, cfg)
	if err == nil {
		t.Fatal("a file with no execute bit resolved")
	}
	if !errors.Is(err, errNotExecutable) {
		t.Errorf("err = %v, want errNotExecutable: a shell exits 126 for this", err)
	}
	if strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %q, which sends the operator to install what is there", err)
	}
	if !strings.Contains(err.Error(), program) {
		t.Errorf("err = %q, want it to name the file", err)
	}

	// With the bit set it resolves, so the check is about the bit and not about
	// the directory.
	if err := os.Chmod(program, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveProgram("deploy", dir, cfg); err != nil {
		t.Errorf("an executable program on the PATH did not resolve: %v", err)
	}

	// And a name nothing on the PATH carries is still not found.
	_, err = resolveProgram("absent-xyzzy", dir, cfg)
	if !errors.Is(err, errNotFound) {
		t.Errorf("err = %v, want errNotFound for a name nothing carries", err)
	}
}

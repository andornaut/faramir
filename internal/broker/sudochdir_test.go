package broker

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Which sudo argv gain -D and which are left as sent. The modes and conflicts
// are the ones real sudo 1.9.15, 1.9.17 and sudo-rs 0.2.13 were seen to reject
// -D with, or to treat differently with it.
func TestSudoChdirRewritesOnlyACommandRunAsRoot(t *testing.T) {
	const cwd = "/srv/tree"
	rewritten := func(args ...string) []string {
		return append([]string{"sudo", "-D", cwd}, args...)
	}
	for _, tc := range []struct {
		name string
		args []string
		want []string // nil: left as sent
	}{
		{"a bare command", []string{"id"}, rewritten("id")},
		{"a command with its own options", []string{"ls", "-l", "-D", "x"},
			rewritten("ls", "-l", "-D", "x")},
		{"flags before the command", []string{"-n", "-E", "id"}, rewritten("-n", "-E", "id")},
		{"a flag cluster", []string{"-nE", "id"}, rewritten("-nE", "id")},
		{"-k with a command", []string{"-k", "id"}, rewritten("-k", "id")},
		{"-- before the command", []string{"-n", "--", "id"}, rewritten("-n", "--", "id")},
		{"-- before a dash-led command", []string{"--", "-x"}, rewritten("--", "-x")},
		{"an environment assignment", []string{"FOO=bar", "env"}, rewritten("FOO=bar", "env")},
		{"-u root", []string{"-u", "root", "id"}, rewritten("-u", "root", "id")},
		{"-uroot", []string{"-uroot", "id"}, rewritten("-uroot", "id")},
		{"-u #0", []string{"-u", "#0", "id"}, rewritten("-u", "#0", "id")},
		{"-nu root", []string{"-nu", "root", "id"}, rewritten("-nu", "root", "id")},
		{"--user=root", []string{"--user=root", "id"}, rewritten("--user=root", "id")},
		{"--user root", []string{"--user", "root", "id"}, rewritten("--user", "root", "id")},
		{"-u root -g a group", []string{"-u", "root", "-g", "adm", "id"},
			rewritten("-u", "root", "-g", "adm", "id")},
		// The value of an option is not the command, even where it reads like one.
		{"a prompt that looks like a command", []string{"-p", "id", "true"},
			rewritten("-p", "id", "true")},
		{"--prompt=value", []string{"--prompt=x", "id"}, rewritten("--prompt=x", "id")},
		{"-C with its value joined", []string{"-C5", "id"}, rewritten("-C5", "id")},
		{"--preserve-env=list", []string{"--preserve-env=PATH", "id"},
			rewritten("--preserve-env=PATH", "id")},
		{"--preserve-env alone", []string{"--preserve-env", "id"},
			rewritten("--preserve-env", "id")},

		// A directory already chosen. Both sudos reject -D twice or apply only one.
		{"-D DIR", []string{"-D", "/x", "id"}, nil},
		{"-DDIR", []string{"-D/x", "id"}, nil},
		{"-D in a cluster", []string{"-nD/x", "id"}, nil},
		{"--chdir DIR", []string{"--chdir", "/x", "id"}, nil},
		{"--chdir=DIR", []string{"--chdir=/x", "id"}, nil},
		// A directory sudo chooses itself.
		{"-i", []string{"-i", "id"}, nil},
		{"--login", []string{"--login", "id"}, nil},
		{"-s", []string{"-s", "id"}, nil},
		{"--shell", []string{"--shell"}, nil},
		{"-i in a cluster", []string{"-ni", "id"}, nil},
		// A mode that runs no command, or that sudo-rs refuses -D with.
		{"-e", []string{"-e", "/etc/hosts"}, nil},
		{"--edit", []string{"--edit", "/etc/hosts"}, nil},
		{"-l", []string{"-l"}, nil},
		{"-l with a command", []string{"-l", "id"}, nil},
		{"-v", []string{"-v"}, nil},
		{"-k alone", []string{"-k"}, nil},
		{"-K", []string{"-K"}, nil},
		{"-V", []string{"-V"}, nil},
		{"-h", []string{"-h"}, nil},
		{"--help", []string{"--help"}, nil},
		{"-h host", []string{"-h", "example.com", "id"}, nil},
		{"-R", []string{"-R", "/chroot", "id"}, nil},
		{"--chroot", []string{"--chroot=/chroot", "id"}, nil},
		// No command at all.
		{"no arguments", nil, nil},
		{"options only", []string{"-n"}, nil},
		{"an option missing its value", []string{"-u"}, nil},
		{"-- and nothing after it", []string{"--"}, nil},
		// Another account enters the directory under -D, where it inherits it today.
		{"-u another account", []string{"-u", "nobody", "id"}, nil},
		{"-u a uid", []string{"-u", "#1000", "id"}, nil},
		{"--user another account", []string{"--user=nobody", "id"}, nil},
		{"-g without -u", []string{"-g", "adm", "id"}, nil},
		{"--group without -u", []string{"--group=adm", "id"}, nil},
		// What this does not know, it leaves alone.
		{"an unknown short option", []string{"-Z", "id"}, nil},
		{"an unknown long option", []string{"--frobnicate", "id"}, nil},
		{"an abbreviated long option", []string{"--chd=/x", "id"}, nil},
		{"a flag given a value", []string{"--stdin=x", "id"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argv := append([]string{"sudo"}, tc.args...)
			sent := slices.Clone(argv)
			got, ok := sudoChdir(cwd, argv)
			want := tc.want
			if want == nil {
				want = sent
			}
			if ok != (tc.want != nil) || !slices.Equal(got, want) {
				t.Errorf("sudoChdir(%q) = %q, %v; want %q, %v", sent, got, ok, want, tc.want != nil)
			}
			if !slices.Equal(argv, sent) {
				t.Errorf("the caller's argv was changed to %q", argv)
			}
		})
	}
}

// fakeSudo puts an executable named sudo on [command.env] PATH and returns its
// path, so the broker's identity check has a host sudo to compare against.
func fakeSudo(t *testing.T, s *Server) string {
	t.Helper()
	dir := t.TempDir()
	sudo := filepath.Join(dir, "sudo")
	if err := os.WriteFile(sudo, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.Config.Command.Env["PATH"] = dir + ":" + s.Config.Command.Env["PATH"]
	return sudo
}

// A sudo on a host that can escalate starts in / with -D naming the caller's
// cwd. The question and both records keep the argv as sent, and the records say
// what the executor was given.
func TestABrokeredSudoStartsInRootAndIsToldTheCwd(t *testing.T) {
	s, rec := execServer(t)
	allowSudo(t, s)
	sudo := fakeSudo(t, s)
	cwd := t.TempDir()

	r := exec(t, s, map[string]any{"cmd": []any{"sudo", "-n", "id"}, "cwd": cwd})
	if r["error"] != nil {
		t.Fatalf("error: %v", r["error"])
	}
	req := rec.only(t)
	if want := []string{sudo, "-D", cwd, "-n", "id"}; !slices.Equal(req.Argv, want) {
		t.Errorf("the executor ran %q, want %q", req.Argv, want)
	}
	if req.Cwd != "/" {
		t.Errorf("the executor started it in %q, want /", req.Cwd)
	}
	all := records(t, s)
	if len(all) != 2 {
		t.Fatalf("records = %d, want run_started and run", len(all))
	}
	for _, record := range all {
		cmd, _ := record["cmd"].([]any)
		if len(cmd) != 3 || cmd[0] != "sudo" || cmd[1] != "-n" || cmd[2] != "id" {
			t.Errorf("%v record cmd = %v, want the caller's argv", record["op"], cmd)
		}
		if record["cwd"] != cwd || record["sudo_chdir"] != cwd {
			t.Errorf("%v record cwd = %v, sudo_chdir = %v; want both %q",
				record["op"], record["cwd"], record["sudo_chdir"], cwd)
		}
	}
}

// Left as sent: a sudo on a host that grants no escalation, which cannot be
// approved, and a program named sudo that is not the one on PATH.
func TestOnlyTheHostsSudoOnAGrantingHostIsRewritten(t *testing.T) {
	for _, tc := range []struct {
		name    string
		granted bool
		other   bool
	}{
		{"no grant", false, false},
		{"another program named sudo", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, rec := execServer(t)
			if tc.granted {
				allowSudo(t, s)
			}
			program := fakeSudo(t, s)
			cwd := t.TempDir()
			if tc.other {
				program = filepath.Join(cwd, "sudo")
				if err := os.WriteFile(program, []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			r := exec(t, s, map[string]any{"cmd": []any{program, "id"}, "cwd": cwd})
			if r["error"] != nil {
				t.Fatalf("error: %v", r["error"])
			}
			req := rec.only(t)
			if req.Cwd != cwd || slices.Contains(req.Argv, "-D") {
				t.Errorf("the executor ran %q in %q, want it as sent in %q", req.Argv, req.Cwd, cwd)
			}
			if record := lastRecord(t, s); record["sudo_chdir"] != nil {
				t.Errorf("the record carries sudo_chdir %v for a run left as sent", record["sudo_chdir"])
			}
		})
	}
}

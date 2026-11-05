package broker

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// How each sudo argv is started. The modes and conflicts are the ones real sudo
// 1.9.15, 1.9.17 and sudo-rs 0.2.13 were seen to reject -D with, or to treat
// differently with it.
func TestPlanSudoRewritesOnlyWhatRootEntersForIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want sudoStart
	}{
		{"a bare command", []string{"id"}, sudoWithChdir},
		{"a command with its own options", []string{"ls", "-l", "-D", "x"}, sudoWithChdir},
		{"flags before the command", []string{"-n", "-E", "id"}, sudoWithChdir},
		{"a flag cluster", []string{"-nE", "id"}, sudoWithChdir},
		{"-k with a command", []string{"-k", "id"}, sudoWithChdir},
		{"-- before the command", []string{"-n", "--", "id"}, sudoWithChdir},
		{"-- before a dash-led command", []string{"--", "-x"}, sudoWithChdir},
		{"an environment assignment", []string{"FOO=bar", "env"}, sudoWithChdir},
		{"-u root", []string{"-u", "root", "id"}, sudoWithChdir},
		{"-uroot", []string{"-uroot", "id"}, sudoWithChdir},
		{"-u #0", []string{"-u", "#0", "id"}, sudoWithChdir},
		{"-nu root", []string{"-nu", "root", "id"}, sudoWithChdir},
		{"--user=root", []string{"--user=root", "id"}, sudoWithChdir},
		{"--user root", []string{"--user", "root", "id"}, sudoWithChdir},
		{"-u root -g a group", []string{"-u", "root", "-g", "adm", "id"}, sudoWithChdir},
		// The value of an option is not the command, even where it reads like one.
		{"a prompt that looks like a command", []string{"-p", "id", "true"}, sudoWithChdir},
		{"--prompt=value", []string{"--prompt=x", "id"}, sudoWithChdir},
		{"-C with its value joined", []string{"-C5", "id"}, sudoWithChdir},
		{"--preserve-env=list", []string{"--preserve-env=PATH", "id"}, sudoWithChdir},
		{"--preserve-env alone", []string{"--preserve-env", "id"}, sudoWithChdir},

		// A login shell changes to the target's home wherever it starts, so it
		// starts in / without -D, for any account and with or without a command.
		{"-i with a command", []string{"-i", "id"}, sudoLogin},
		{"-i alone", []string{"-i"}, sudoLogin},
		{"--login", []string{"--login", "id"}, sudoLogin},
		{"-i in a cluster", []string{"-ni", "id"}, sudoLogin},
		{"-i in a cluster before a value", []string{"-iu", "root", "id"}, sudoLogin},
		{"-i after other options", []string{"-n", "-u", "root", "-i", "id"}, sudoLogin},
		{"-i as another account", []string{"-i", "-u", "nobody"}, sudoLogin},
		{"-i -g without -u", []string{"-i", "-g", "adm"}, sudoLogin},
		{"--login given a value", []string{"--login=x", "id"}, sudoAsSent},
		{"-i with -D", []string{"-i", "-D", "/x", "id"}, sudoAsSent},
		{"-i with -s", []string{"-i", "-s"}, sudoAsSent},
		{"-i with -l", []string{"-i", "-l"}, sudoAsSent},
		{"-i with -e", []string{"-i", "-e", "/etc/hosts"}, sudoAsSent},
		{"-i missing an option's value", []string{"-i", "-u"}, sudoAsSent},

		// A directory already chosen. Both sudos reject -D twice or apply only one.
		{"-D DIR", []string{"-D", "/x", "id"}, sudoAsSent},
		{"-DDIR", []string{"-D/x", "id"}, sudoAsSent},
		{"-D in a cluster", []string{"-nD/x", "id"}, sudoAsSent},
		{"--chdir DIR", []string{"--chdir", "/x", "id"}, sudoAsSent},
		{"--chdir=DIR", []string{"--chdir=/x", "id"}, sudoAsSent},
		// -s runs the shell in the directory it was started in.
		{"-s", []string{"-s", "id"}, sudoAsSent},
		{"--shell", []string{"--shell"}, sudoAsSent},
		// A mode that runs no command, or that sudo-rs refuses -D with.
		{"-e", []string{"-e", "/etc/hosts"}, sudoAsSent},
		{"--edit", []string{"--edit", "/etc/hosts"}, sudoAsSent},
		{"-l", []string{"-l"}, sudoAsSent},
		{"-l with a command", []string{"-l", "id"}, sudoAsSent},
		{"-v", []string{"-v"}, sudoAsSent},
		{"-k alone", []string{"-k"}, sudoAsSent},
		{"-K", []string{"-K"}, sudoAsSent},
		{"-V", []string{"-V"}, sudoAsSent},
		{"-h", []string{"-h"}, sudoAsSent},
		{"--help", []string{"--help"}, sudoAsSent},
		{"-h host", []string{"-h", "example.com", "id"}, sudoAsSent},
		{"-R", []string{"-R", "/chroot", "id"}, sudoAsSent},
		{"--chroot", []string{"--chroot=/chroot", "id"}, sudoAsSent},
		// No command at all.
		{"no arguments", nil, sudoAsSent},
		{"options only", []string{"-n"}, sudoAsSent},
		{"an option missing its value", []string{"-u"}, sudoAsSent},
		{"-- and nothing after it", []string{"--"}, sudoAsSent},
		// Another account enters the directory under -D, where it inherits it today.
		{"-u another account", []string{"-u", "nobody", "id"}, sudoAsSent},
		{"-u a uid", []string{"-u", "#1000", "id"}, sudoAsSent},
		{"--user another account", []string{"--user=nobody", "id"}, sudoAsSent},
		{"-g without -u", []string{"-g", "adm", "id"}, sudoAsSent},
		{"--group without -u", []string{"--group=adm", "id"}, sudoAsSent},
		// What this does not know, it leaves alone.
		{"an unknown short option", []string{"-Z", "id"}, sudoAsSent},
		{"an unknown long option", []string{"--frobnicate", "id"}, sudoAsSent},
		{"an abbreviated long option", []string{"--chd=/x", "id"}, sudoAsSent},
		{"a flag given a value", []string{"--stdin=x", "id"}, sudoAsSent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argv := append([]string{"sudo"}, tc.args...)
			if got := planSudo(argv); got != tc.want {
				t.Errorf("planSudo(%q) = %v, want %v", argv, got, tc.want)
			}
		})
	}
}

// What each plan hands the executor: -D goes straight after argv[0], and the
// caller's argv is never changed in place.
func TestExecTargetStartsEachPlanWhereItSays(t *testing.T) {
	dir := t.TempDir()
	sudo := filepath.Join(dir, "sudo")
	if err := os.WriteFile(sudo, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	execCfg := config.CommandConfig{Env: map[string]string{"PATH": dir}}
	const cwd = "/srv/tree"
	for _, tc := range []struct {
		name              string
		cmd, argv         []string
		dir, chdir, runID string
	}{
		{"-D after argv[0]", []string{"sudo", "-n", "id"},
			[]string{sudo, "-D", cwd, "-n", "id"}, "/", cwd, "run"},
		{"a login shell in /", []string{"sudo", "-i", "id"},
			[]string{sudo, "-i", "id"}, "/", "", "run"},
		{"-s as sent", []string{"sudo", "-s", "id"},
			[]string{sudo, "-s", "id"}, cwd, "", "run"},
		{"no run id", []string{"sudo", "id"},
			[]string{sudo, "id"}, cwd, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sent := slices.Clone(tc.cmd)
			argv, gotDir, chdir := execTarget(execCfg, tc.runID, sudo, cwd, tc.cmd)
			if !slices.Equal(argv, tc.argv) || gotDir != tc.dir || chdir != tc.chdir {
				t.Errorf("execTarget = %q in %q, -D %q; want %q in %q, -D %q",
					argv, gotDir, chdir, tc.argv, tc.dir, tc.chdir)
			}
			if !slices.Equal(tc.cmd, sent) {
				t.Errorf("the caller's argv was changed to %q", tc.cmd)
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
		if record["started_in"] != "/" {
			t.Errorf("%v record started_in = %v, want /", record["op"], record["started_in"])
		}
	}
}

// A login shell starts in / as sent, and its records say where it started and
// that no -D was added.
func TestABrokeredLoginShellStartsInRoot(t *testing.T) {
	s, rec := execServer(t)
	allowSudo(t, s)
	sudo := fakeSudo(t, s)
	cwd := t.TempDir()

	r := exec(t, s, map[string]any{"cmd": []any{"sudo", "-i", "id"}, "cwd": cwd})
	if r["error"] != nil {
		t.Fatalf("error: %v", r["error"])
	}
	req := rec.only(t)
	if want := []string{sudo, "-i", "id"}; !slices.Equal(req.Argv, want) || req.Cwd != "/" {
		t.Errorf("the executor ran %q in %q, want %q in /", req.Argv, req.Cwd, want)
	}
	for _, record := range records(t, s) {
		if record["cwd"] != cwd || record["started_in"] != "/" || record["sudo_chdir"] != nil {
			t.Errorf("%v record cwd = %v, started_in = %v, sudo_chdir = %v; want %q, /, none",
				record["op"], record["cwd"], record["started_in"], record["sudo_chdir"], cwd)
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
			if record := lastRecord(t, s); record["sudo_chdir"] != nil || record["started_in"] != nil {
				t.Errorf("the record carries sudo_chdir %v, started_in %v for a run left as sent",
					record["sudo_chdir"], record["started_in"])
			}
		})
	}
}

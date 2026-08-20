package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeVisudo writes a program that answers -V with the line given, and fails
// every other invocation the way a visudo rejecting a file does.
func fakeVisudo(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "visudo")
	script := "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then printf '%s\\n' " +
		"'" + version + "'; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// The note is about a version floor, so it belongs only where the version could
// be the cause. noninteractive_auth arrived in sudo 1.9.11 and sudo-rs 0.2.9;
// on anything newer a rejection is about the file, which visudo has already
// explained, and a note would send an operator after an upgrade they do not need.
func TestTheVersionNoteFiresOnlyWhereTheVersionIsTheCause(t *testing.T) {
	for version, want := range map[string]string{
		"sudo-rs 0.2.2":         "sudo-rs 0.2.9",
		"sudo-rs 0.1.0":         "sudo-rs 0.2.9",
		"Sudo version 1.9.5p2":  "sudo 1.9.11",
		"Sudo version 1.8.31":   "sudo 1.9.11",
		"sudo-rs 0.2.13":        "",
		"visudo-rs 0.2.14":      "",
		"Sudo version 1.9.15p5": "",
		"Sudo version 1.9.17p2": "",
		"some other sudo":       "",
	} {
		note := sudoRsNote(fakeVisudo(t, version))
		if want == "" {
			if note != "" {
				t.Errorf("%q drew a version note and is not older than the floor: %s",
					version, note)
			}
			continue
		}
		if note == "" {
			t.Errorf("%q is older than the floor and drew no note", version)
			continue
		}
		if !strings.Contains(note, want) {
			t.Errorf("%q drew a note naming neither %q nor its own floor: %s",
				version, want, note)
		}
		if !strings.Contains(note, strings.TrimSpace(version)) {
			t.Errorf("the note does not say what %q reports: %s", version, note)
		}
		if !strings.Contains(note, "noninteractive_auth") {
			t.Errorf("the note does not name the setting that is missing: %s", note)
		}
	}
}

// A visudo that cannot be asked its version says nothing rather than guessing.
// The rejection is reported either way; this only adds a cause.
func TestAVisudoThatWillNotReportItsVersionAddsNothing(t *testing.T) {
	if note := sudoRsNote(filepath.Join(t.TempDir(), "not-there")); note != "" {
		t.Errorf("an unreadable visudo drew a note: %s", note)
	}
}

// What the probe answers decides which arrangement a host gets, so it has to
// read a version banner rather than a package name. Both of sudo-rs's binaries
// say so in their own; the original says "Sudo version".
func TestTheProbeReadsTheVersionBanner(t *testing.T) {
	for version, want := range map[string]bool{
		"sudo-rs 0.2.13-0ubuntu1": true,
		"visudo-rs 0.2.14":        true,
		"Sudo version 1.9.17p2":   false,
		"visudo version 1.9.17p2": false,
		// sudo-rs 0.2.2 names no implementation in visudo's banner at all, and
		// reads like the original's. The version is the only thing that separates
		// them: the original has been past 1.0 since long before either existed.
		"visudo version 0.2.2": true,
		"sudo-rs 0.2.2":        true,
	} {
		dir := filepath.Dir(fakeVisudo(t, version))
		t.Setenv("PATH", dir)
		if got := probeSudoRs(); got != want {
			t.Errorf("%q probed as sudo-rs=%v, want %v", version, got, want)
		}
	}
}

// The grant is what each implementation has to parse, and the two settings it
// differs by are the two sudo-rs has no name for. Rendered both ways here, so a
// directive added to the wrong branch is caught before a host refuses the file.
func TestTheGrantCarriesOnlyWhatThisSudoParses(t *testing.T) {
	layout := testLayout()
	for _, rs := range []bool{false, true} {
		layout.SudoRs = rs
		body, err := render("etc/sudoers.tmpl", layout)
		if err != nil {
			t.Fatal(err)
		}
		grant := uncommented(string(body))
		// noninteractive_auth is in both: without it `sudo -n` fails before the PAM
		// stack runs, and ansible's become passes -n by default.
		for _, want := range []string{"noninteractive_auth", "timestamp_timeout=0", "PASSWD:"} {
			if !strings.Contains(grant, want) {
				t.Errorf("sudo-rs=%v: the grant does not carry %q:\n%s", rs, want, grant)
			}
		}
		// Both launch types. sudo authenticates `sudo -i` against a service of its
		// own, so a grant naming only pam_service leaves a login shell escalation
		// reading the stock stack, where the executor's locked password refuses and
		// the question is never put.
		for _, only := range []string{"pam_service=", "pam_login_service="} {
			if strings.Contains(grant, only) == rs {
				t.Errorf("sudo-rs=%v: the grant carries %q, which that sudo does not "+
					"parse:\n%s", rs, only, grant)
			}
		}
		// env_file is in neither: sudo-rs has no such setting, so the environment is
		// read by pam_env in the service on every host rather than two ways.
		if strings.Contains(grant, "env_file=") {
			t.Errorf("sudo-rs=%v: the grant names an env_file:\n%s", rs, grant)
		}
		if strings.Contains(grant, "NOPASSWD") {
			t.Errorf("sudo-rs=%v: the grant is passwordless, which skips PAM and the "+
				"question with it:\n%s", rs, grant)
		}
	}
}

// uncommented is a rendered sudoers file with its comments taken out, so a
// setting named only in the prose above the file is not read as one the file
// sets.
func uncommented(body string) string {
	var out strings.Builder
	for line := range strings.Lines(body) {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out.WriteString(line)
	}
	return out.String()
}

// The permit ends the stack it is in, and the two stacks are not the same shape.
// faramir's own service file is the whole of a stack, so `required` there is the
// end of it. The block is a branch inside a stack that continues, so its permit
// must be `sufficient` or the executor carries on to the password check that
// stack has for everybody else, which a locked account cannot pass.
func TestThePermitEndsTheStackItIsIn(t *testing.T) {
	layout := testLayout()
	for asset, want := range map[string]string{
		"etc/pam.d.tmpl":      "required",
		"etc/pam.d-sudo.tmpl": "sufficient",
	} {
		body, err := render(asset, layout)
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.Lines(uncommented(string(body))) {
			if !strings.Contains(line, "pam_permit.so") || !strings.HasPrefix(line, "auth") {
				continue
			}
			if !strings.Contains(line, want) {
				t.Errorf("%s: the permit is %q, want %q", asset,
					strings.TrimSpace(line), want)
			}
		}
	}
}

// The environment reaches root the same way on both: pam_env in faramir's own
// service. sudoers has an env_file that does the same job, but sudo-rs has no
// such setting, and one mechanism that works everywhere beats two that each work
// in one place. Without it FARAMIR_OPERATOR and [command] env are dropped at the
// sudo and nothing says so.
func TestOneMechanismCarriesTheEnvironmentAcrossSudo(t *testing.T) {
	layout := testLayout()
	// Whichever file is the stack on that host reads it with pam_env, and the
	// grant names it on neither: sudo-rs has no env_file.
	for _, asset := range []string{"etc/pam.d.tmpl", "etc/pam.d-sudo.tmpl"} {
		stack, err := render(asset, layout)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(uncommented(string(stack)), "pam_env.so") {
			t.Errorf("%s does not read the environment file", asset)
		}
	}
	for _, rs := range []bool{false, true} {
		layout.SudoRs = rs
		grant, err := render("etc/sudoers.tmpl", layout)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(uncommented(string(grant)), "env_file=") {
			t.Errorf("sudo-rs=%v: the grant names an env_file", rs)
		}
	}
}

// The real banners, per version, read off installed binaries: sudo-rs 0.2.9
// through 0.2.14 and the 24.04 package's 0.2.2, against the original sudo. `sudo
// -V` names sudo-rs on every one; `visudo -V` did not until 0.2.11, so a run
// that can reach only visudo has nothing but the version to go on. This pins
// both so a probe change is measured against what the binaries actually say.
func TestTheProbeAgainstEveryRealBanner(t *testing.T) {
	for banner, want := range map[string]bool{
		// sudo -V, which probeSudoRs asks first. Every version names itself.
		"sudo-rs 0.2.2":  true,
		"sudo-rs 0.2.9":  true,
		"sudo-rs 0.2.10": true,
		"sudo-rs 0.2.11": true,
		"sudo-rs 0.2.13": true,
		"sudo-rs 0.2.14": true,
		// visudo -V, the fallback. Unnamed through 0.2.10, named from 0.2.11.
		"visudo version 0.2.2":  true,
		"visudo version 0.2.9":  true,
		"visudo version 0.2.10": true,
		"visudo-rs 0.2.11":      true,
		"visudo-rs 0.2.14":      true,
		// The original, both binaries. Named "Sudo"/"visudo" and past 1.0.
		"Sudo version 1.9.15p5":   false,
		"Sudo version 1.9.17p2":   false,
		"visudo version 1.9.17p2": false,
	} {
		if got := bannerIsSudoRs(banner); got != want {
			t.Errorf("bannerIsSudoRs(%q) = %v, want %v", banner, got, want)
		}
	}
}

// The version floor, against those same real banners: only a release below the
// floor draws a note, and it names the right product's floor. noninteractive_auth
// landed in sudo 1.9.11 and sudo-rs 0.2.9, so 0.2.9 itself is not below it.
func TestTheFloorAgainstEveryRealBanner(t *testing.T) {
	for banner, wantFloor := range map[string]string{
		"sudo-rs 0.2.2":         "sudo-rs 0.2.9", // below: noninteractive_auth not yet there
		"visudo version 0.2.2":  "sudo-rs 0.2.9",
		"sudo-rs 0.2.9":         "", // the floor itself: fine
		"sudo-rs 0.2.14":        "",
		"visudo version 0.2.10": "",
		"Sudo version 1.9.5p2":  "sudo 1.9.11",
		"Sudo version 1.9.11":   "",
		"Sudo version 1.9.17p2": "",
	} {
		note := sudoRsNote(fakeVisudo(t, banner))
		if wantFloor == "" {
			if note != "" {
				t.Errorf("%q is at or above the floor but drew a note: %s", banner, note)
			}
			continue
		}
		if !strings.Contains(note, wantFloor) {
			t.Errorf("%q drew %q, want a note naming %q", banner, note, wantFloor)
		}
	}
}

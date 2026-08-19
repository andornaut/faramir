package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// configDirWith is an install directory holding this config.toml, for the
// commands that take a directory and join the file name onto it.
func configDirWith(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const sharedGroupConfig = "[command]\ntimeout_sec = 600\n\n[server]\nallowed_group = \"faramir-clients\"\n"

// allowed_group is what the broker socket admits, so it is the only value that
// makes a shared tree usable: a tree shared with any other group is one the
// executor can enter and the broker will not serve.
func TestTheClientGroupIsReadOffTheInstalledConfig(t *testing.T) {
	run := &project{opts: ProjectOptions{ConfigDir: configDirWith(t, sharedGroupConfig)}}

	if err := run.resolveGroup(); err != nil {
		t.Fatal(err)
	}
	if run.report.ClientGroup != "faramir-clients" {
		t.Errorf("group = %q, want the one the config admits", run.report.ClientGroup)
	}
	if run.allowSudo {
		t.Error("a config with no [escalation] exec_user was read as granting sudo")
	}
}

// A config whose allowed_group was emptied by hand is refused rather than
// shared with nothing: the walk would run, regroup the tree to whatever it
// resolved, and leave a tree the broker still will not serve.
func TestAConfigThatAdmitsNoGroupIsRefused(t *testing.T) {
	run := &project{opts: ProjectOptions{
		ConfigDir: configDirWith(t,
			"[command]\ntimeout_sec = 600\n\n[server]\nallowed_group = \"\"\n"),
	}}

	err := run.resolveGroup()

	if err == nil {
		t.Fatal("an enrolment against a config that admits no group was accepted")
	}
	if !strings.Contains(err.Error(), "--client-group") {
		t.Errorf("err = %v, want it to name the command that sets one", err)
	}
}

// No config and no flag: the enrolment cannot name the group, and the message
// carries all three ways out rather than only the first.
func TestAnEnrolmentWithNoConfigToReadSaysWhatToDo(t *testing.T) {
	run := &project{opts: ProjectOptions{ConfigDir: t.TempDir()}}

	err := run.resolveGroup()

	if err == nil {
		t.Fatal("an enrolment with no config to read was accepted")
	}
	for _, want := range []string{"faramir init", "--config-dir", "--client-group"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to name %q", err, want)
		}
	}
}

// --client-group names an install this machine need not have, so an unreadable
// config is not an error. What it must not do is take anything else off this
// host's config: the sudo grant decides a paragraph of the credentials section,
// and a section describing an escalation that cannot be raised here is one the
// agent learns to skim.
func TestANamedGroupTakesTheSudoGrantOnlyFromTheSameInstall(t *testing.T) {
	const granted = sharedGroupConfig + "\n[escalation]\nexec_user = \"faramir-exec\"\n"
	for _, tc := range []struct {
		name string
		// config is the file this host carries; empty writes none at all.
		config string
		group  string
		want   bool
	}{
		{
			// The config loads and admits the group just named, which is what says
			// the two are one install.
			name:   "the config admits the group that was named",
			config: granted,
			group:  "faramir-clients",
			want:   true,
		},
		{
			name:   "the config admits some other group",
			config: granted,
			group:  "another-install",
			want:   false,
		},
		{
			name:  "there is no config to read",
			group: "faramir-clients",
			want:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configDir := t.TempDir()
			if tc.config != "" {
				configDir = configDirWith(t, tc.config)
			}
			run := &project{opts: ProjectOptions{
				ConfigDir: configDir, ClientGroup: tc.group,
			}}

			if err := run.resolveGroup(); err != nil {
				t.Fatalf("a named group was refused: %v", err)
			}
			if run.report.ClientGroup != tc.group {
				t.Errorf("group = %q, want the one that was named", run.report.ClientGroup)
			}
			if run.allowSudo != tc.want {
				t.Errorf("allowSudo = %v, want %v", run.allowSudo, tc.want)
			}
		})
	}
}

// And the paragraph follows the grant: what an enrolment writes into the tree
// is decided by what resolveGroup read, so the two are asserted together rather
// than each against its own fixture.
func TestTheSectionFollowsTheGrantTheEnrolmentRead(t *testing.T) {
	const marker = "escalation_in_progress"
	run := &project{opts: ProjectOptions{
		ConfigDir: configDirWith(t,
			sharedGroupConfig+"\n[escalation]\nexec_user = \"faramir-exec\"\n"),
	}}
	if err := run.resolveGroup(); err != nil {
		t.Fatal(err)
	}

	body, err := credentialsSection(run.allowSudo)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, marker) {
		t.Errorf("a tree enrolled on a sudo host is not told about %s", marker)
	}
}

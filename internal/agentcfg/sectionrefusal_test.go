package agentcfg

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostfs"
)

// A credentials section an earlier version wrote, or one somebody reworded, is
// left where it is and the run stops. Appending would leave the file carrying
// two sets of credentials instructions that contradict each other, and the
// wrap cannot take this one, matching the shipped text exactly.
//
// The file is byte-for-byte what it was: every error sectionFile returns of its
// own leaves it alone, which is what makes the message safe to act on.
func TestARewordedSectionStopsTheWriteAndKeepsTheFile(t *testing.T) {
	body := section(t)
	heading, _, ok := strings.Cut(body, "\n")
	if !ok {
		t.Fatal("the section has no heading, so nothing marks a reworded copy")
	}
	before := "# Project\n\n" + heading + "\n\nRun things through faramir, or so we used to.\n"
	path := filepath.Join(t.TempDir(), "AGENTS.md")
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}

	changed, err := SectionFile(hostfs.FS{}, path, body, "", hostfs.Keep, hostfs.Keep, "")

	if !errors.Is(err, errStaleSection) {
		t.Fatalf("sectionFile = (%v, %v), want errStaleSection", changed, err)
	}
	if changed {
		t.Error("a file that was left alone was reported as changed")
	}
	if after, readErr := os.ReadFile(path); readErr != nil {
		t.Fatal(readErr)
	} else if string(after) != before {
		t.Errorf("the file was rewritten:\n%s", after)
	}
}

// Each refusal says what to do, not only what happened: the file it is about,
// the command that writes the section afresh, and for the marker cases what the
// markers are. An operator reading one of these is being asked to edit their
// own prose, so the message has to carry enough to do it by.
func TestEveryRefusalNamesTheFileAndTheCommandToRunAgain(t *testing.T) {
	const path = "/home/operator/project/AGENTS.md"
	const command = "`sudo faramir enrol`"
	for _, tc := range []struct {
		name string
		err  error
		// says is what the message has to carry beyond the path and the command.
		says []string
	}{
		{"one marker without the other", errHalfMarked, []string{SectionBegin, SectionEnd}},
		{"an undelimited section", errStaleSection, []string{SectionBegin, SectionEnd}},
		{"a file that is not the operator's", hostfs.ErrNotOperators, []string{"symlink"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SectionProblem(tc.err, path, command)

			for _, want := range append([]string{path, command}, tc.says...) {
				if !strings.Contains(got, want) {
					t.Errorf("the message does not carry %q:\n%s", want, got)
				}
			}
			// And each is fatal to the run: these files carry the policy an agent is
			// held to, and a run reporting success having failed to update one leaves
			// an operator believing a host says something it does not.
			if !OutOfDate(tc.err) {
				t.Errorf("%v is not treated as leaving the section out of date", tc.err)
			}
		})
	}
}

// Anything else is passed through as it is rather than dressed up as one of
// these: a message telling an operator to delete a section they do not have
// sends them looking for it.
func TestAnErrorThatIsNoneOfThemIsReportedAsItIs(t *testing.T) {
	other := errors.New("no space left on device")

	if got := SectionProblem(other, "/tmp/AGENTS.md", "`faramir init`"); got != other.Error() {
		t.Errorf("sectionProblem = %q, want the error itself", got)
	}
	if OutOfDate(other) {
		t.Error("an unrelated error was treated as leaving the section out of date")
	}
}

// Both signs are needed to call an unmarked file stale. The heading alone is
// something an operator may write about their own credentials, and naming the
// tool alone is the file the markers exist to unblock. A section with no
// heading at all marks nothing, and this says so rather than matching every
// file that mentions faramir.
func TestWhatCountsAsAnUndelimitedSection(t *testing.T) {
	body := section(t)
	heading, _, _ := strings.Cut(body, "\n")
	for _, tc := range []struct {
		name    string
		current string
		body    string
		want    bool
	}{
		{"the heading and the tool", heading + "\n\nWe use faramir here.\n", body, true},
		{"the heading alone", heading + "\n\nMy own keys.\n", body, false},
		{"the tool alone", "# Notes\n\nWe use faramir here.\n", body, false},
		{"a section with no heading to find", "faramir\n", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := carriesAStaleSection([]byte(tc.current), tc.body); got != tc.want {
				t.Errorf("carriesAStaleSection = %v, want %v", got, tc.want)
			}
		})
	}
}

// A link is followed only to a regular file the operator owns. `init` runs as
// root on a path inside a directory the account the agent runs as can write, so
// a link re-pointed at a file root can write would otherwise turn this into an
// append as root.
func TestALinkToAFileTheOperatorDoesNotOwnIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "AGENTS.md")
	target := filepath.Join(dir, "somebody-elses.md")
	const before = "# Not yours\n"
	if err := os.WriteFile(target, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	// An operator that is not this file's owner, which is what the check asks.
	_, err := SectionFile(hostfs.FS{}, path, section(t), "", os.Getuid()+1, hostfs.Keep, "")

	if !errors.Is(err, hostfs.ErrNotOperators) {
		t.Fatalf("err = %v, want the link refused", err)
	}
	if !OutOfDate(err) {
		t.Error("a link this will not follow does not fail the run")
	}
	if body, readErr := os.ReadFile(target); readErr != nil {
		t.Fatal(readErr)
	} else if string(body) != before {
		t.Errorf("the file was written anyway:\n%s", body)
	}
}

// A link naming a path that is not there is refused rather than created
// through: this runs as root, so creating it would put a root-made file
// wherever the link happens to aim.
func TestADanglingLinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "AGENTS.md")
	target := filepath.Join(dir, "nothing-here.md")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	_, err := SectionFile(hostfs.FS{}, path, section(t), "", hostfs.Keep, hostfs.Keep, "")

	if !errors.Is(err, hostfs.ErrNotOperators) {
		t.Fatalf("err = %v, want the link refused", err)
	}
	if hostfs.Exists(target) {
		t.Error("the dangling link was created through")
	}
}

// A dry run is the one form that does not need root, so a file it cannot read
// is reported as no change rather than stopping the run, as EnsureDir does for
// a directory it cannot look inside.
func TestADryRunSurvivesAnUnreadableInstructionsFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read the file this makes unreadable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "AGENTS.md")
	if err := os.WriteFile(path, []byte("# Project\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	changed, err := SectionFile(hostfs.FS{DryRun: true}, path, section(t), "", hostfs.Keep, hostfs.Keep, "")
	if err != nil {
		t.Fatalf("a dry run stopped on a file it cannot read: %v", err)
	}
	if changed {
		t.Error("a file that could not be read was reported as changed")
	}
}

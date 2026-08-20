package escalation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The broker and the installer have to agree about where the stack that decides
// an escalation is, and the two sudo implementations put it in different places.
// A lookup that knew only one of them reports a working host as one that cannot
// escalate, which fails an install after the grant is already on disk.
func TestStackFileFindsEitherArrangement(t *testing.T) {
	dir := t.TempDir()
	const service = "faramir-sudo"

	if _, err := StackFile(dir, service); err == nil {
		t.Error("a host with neither arrangement reported a stack")
	}

	// The shared stacks exist but say nothing of faramir's: still no stack.
	for _, name := range []string{"sudo", "sudo-i"} {
		if err := os.WriteFile(filepath.Join(dir, name),
			[]byte("@include common-auth\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := StackFile(dir, service); err == nil {
		t.Error("a stock stack with no block reported a stack")
	} else if !strings.Contains(err.Error(), service) {
		t.Errorf("the error does not name the service it looked for: %v", err)
	}

	// sudo-rs: a block, and no service file.
	block := BlockBegin + "\nauth requisite pam_exec.so\n" + BlockEnd + "\n"
	if err := os.WriteFile(filepath.Join(dir, "sudo"),
		[]byte(block+"@include common-auth\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := StackFile(dir, service)
	if err != nil || got != filepath.Join(dir, "sudo") {
		t.Errorf("found %q (%v), want the shared stack", got, err)
	}

	// The original: a service file, which is what sudo would be sent to.
	if err := os.WriteFile(filepath.Join(dir, service),
		[]byte("auth requisite pam_exec.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err = StackFile(dir, service); err != nil || got != filepath.Join(dir, service) {
		t.Errorf("found %q (%v), want the service file", got, err)
	}
}

// A stray marker is not a block. Answering for a host on the strength of one
// would report a stack that cannot be read off the file as one that decides.
func TestHasBlockNeedsBothMarkersOnLinesOfTheirOwn(t *testing.T) {
	for body, want := range map[string]bool{
		BlockBegin + "\nauth optional pam_permit.so\n" + BlockEnd + "\n":  true,
		BlockBegin + "\nauth optional pam_permit.so\n":                    false,
		"auth optional pam_permit.so\n" + BlockEnd + "\n":                 false,
		"# see '" + BlockBegin + "' and '" + BlockEnd + "' in the docs\n": false,
		"@include common-auth\n":                                          false,
	} {
		if got := HasBlock(body); got != want {
			t.Errorf("got %v, want %v, for:\n%s", got, want, body)
		}
	}
}

// What the install recorded is preferred, and a stale record does not condemn a
// host: an operator who rearranged one by hand, or a config written before the
// key existed, still gets an answer by looking.
func TestStackPrefersWhatWasRecordedAndFallsBackToLooking(t *testing.T) {
	dir := t.TempDir()
	const service = "faramir-sudo"
	own := filepath.Join(dir, service)
	if err := os.WriteFile(own, []byte("auth requisite pam_exec.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	block := BlockBegin + "\nauth requisite pam_exec.so\n" + BlockEnd + "\n"
	shared := filepath.Join(dir, "sudo")
	if err := os.WriteFile(shared, []byte(block), 0o644); err != nil {
		t.Fatal(err)
	}

	// Recorded and there: taken, even though the other arrangement is also
	// present. This is the host that was switched and re-installed.
	if got, err := Stack(dir, shared, service); err != nil || got != shared {
		t.Errorf("got %q (%v), want the recorded stack", got, err)
	}
	// Recorded and gone: looked for rather than reported as broken.
	if got, err := Stack(dir, filepath.Join(dir, "not-there"), service); err != nil || got != own {
		t.Errorf("got %q (%v), want the service file found by looking", got, err)
	}
	// Never recorded, which is every config written before the key existed.
	if got, err := Stack(dir, "", service); err != nil || got != own {
		t.Errorf("got %q (%v), want the service file", got, err)
	}
	// And a host with neither still fails, recorded or not.
	if err := os.Remove(own); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(shared); err != nil {
		t.Fatal(err)
	}
	if _, err := Stack(dir, shared, service); err == nil {
		t.Error("a host with neither arrangement reported a stack")
	}
}

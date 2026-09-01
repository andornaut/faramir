package layouttest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
)

// StockSudoStack is /etc/pam.d/sudo as a distribution ships it: a session
// preamble and the includes that authenticate everybody.
const StockSudoStack = `#%PAM-1.0

session    required   pam_limits.so

@include common-auth
@include common-account
@include common-session-noninteractive
`

// SudoStacks writes both shared stacks into a redirected /etc/pam.d and returns
// the directory.
//
// It redirects the grant and the service file with them. This machine may be a
// granting host: a test that reached the real paths would be one that revoked
// the install it was running on.
func SudoStacks(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pam, grant, service := hostlayout.PamDir, hostlayout.SudoersFile, hostlayout.PamServiceFile
	hostlayout.PamDir = dir
	hostlayout.SudoersFile = filepath.Join(dir, "sudoers-faramir")
	hostlayout.PamServiceFile = filepath.Join(dir, hostlayout.PamServiceName)
	t.Cleanup(func() { hostlayout.PamDir, hostlayout.SudoersFile, hostlayout.PamServiceFile = pam, grant, service })
	for _, name := range []string{"sudo", "sudo-i"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(StockSudoStack), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Uncommented is a rendered sudoers file with its comments taken out, so a
// setting named only in the prose above the file is not read as one the file
// sets.
func Uncommented(body string) string {
	var out strings.Builder
	for line := range strings.Lines(body) {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out.WriteString(line)
	}
	return out.String()
}

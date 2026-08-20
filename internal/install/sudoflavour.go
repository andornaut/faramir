package install

// Which sudo reads what this install writes.
//
// The two implementations share /etc/sudoers.d and take different settings out
// of it, so the grant is rendered for the one that will parse it. sudo-rs has
// neither pam_service nor env_file, which are the two directives the classic
// arrangement is built on, so the difference is not cosmetic: what selects
// faramir's PAM service and what a brokered command keeps across its sudo are
// arranged differently on each.

import (
	"context"
	"os/exec"
	"strings"
)

// sudoRsProbe answers the question, a variable so a test can answer for a host
// whose sudo is the other one. Nothing else here is stubbed: what it returns is
// the only thing the rest of the package reads.
var sudoRsProbe = probeSudoRs

// probeSudoRs reports whether this host's sudo is sudo-rs.
//
// It asks the binaries rather than the distribution. Both are packaged behind
// one `sudo` alternatives group whose members an operator switches between, so
// which one a host has is a question about what /usr/bin/sudo resolves to today
// and not about its release.
//
// sudo first, not visudo, and that is not arbitrary: sudo-rs 0.2.2 answers
// `visudo -V` with "visudo version 0.2.2", which names no implementation and
// reads exactly like the original's banner. Its `sudo -V` says "sudo-rs 0.2.2".
// Asking the binary the grant is actually for is both more direct and the one
// that has answered on every release seen.
//
// A host with neither on PATH is treated as classic, which is the arrangement
// that has to be wrong out loud: visudo is what refuses a grant the host's sudo
// cannot read, and refuseInvalidSudoers runs before anything is written.
func probeSudoRs() bool {
	for _, program := range []string{"sudo", "visudo"} {
		path, err := exec.LookPath(program)
		if err != nil {
			continue
		}
		out, err := exec.CommandContext(context.Background(), path, "-V").CombinedOutput()
		if err != nil {
			continue
		}
		return bannerIsSudoRs(firstLine(string(out)))
	}
	return false
}

// bannerIsSudoRs reads an implementation off a version banner.
//
// "sudo-rs 0.2.13-0ubuntu1" and "visudo-rs 0.2.14" name themselves. "visudo
// version 0.2.2" does not, and is sudo-rs all the same: the version is the only
// thing separating it from the original's "Sudo version 1.9.17p2", the original
// having been past 1.0 since long before either of these existed. So a leading
// 0 answers where the name does not.
//
// That second test stops meaning anything the day sudo-rs releases a 1.0, and it
// is a fallback rather than the answer: probeSudoRs asks `sudo` first, whose
// banner has named itself on every release seen, 0.2.2 included. What this
// covers is the host where only visudo could be reached.
func bannerIsSudoRs(banner string) bool {
	if strings.Contains(strings.ToLower(banner), "sudo-rs") {
		return true
	}
	for field := range strings.FieldsSeq(banner) {
		if !strings.Contains(field, ".") || !strings.ContainsAny(field, "0123456789") {
			continue
		}
		major, _, _ := strings.Cut(field, ".")
		return major == "0"
	}
	return false
}

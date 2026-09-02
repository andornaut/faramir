package hostsudo

// Which sudo this host has, and whether it is new enough for the grant.

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// VersionNote names the version floor the grant sits on, or "".
//
// The grant is rendered for whichever sudo this host has, so a rejection is no
// longer a question of which implementation is installed but of how old it is.
// Both grew `noninteractive_auth` after their first releases, and it is the one
// setting here that a sudo old enough will not know: `unknown setting` from
// visudo reads as a typo in a directive faramir wrote deliberately, and every
// other line of the grant is reported as invalid with it.
//
// Read only once the check has failed. A version probe on every install would be
// a command run to say nothing on every host that works.
func VersionNote(visudo string) string {
	out, err := exec.CommandContext(context.Background(), visudo, "-V").CombinedOutput()
	if err != nil {
		return ""
	}
	banner := strings.TrimSpace(firstLine(string(out)))
	floor, older := "sudo 1.9.11", olderThanFloor(banner)
	// bannerIsSudoRs, not a substring: sudo-rs 0.2.2 answers visudo -V with
	// "visudo version 0.2.2" and names no implementation, and that is exactly the
	// release this note is most likely to be printed for.
	if bannerIsRs(banner) {
		floor = "sudo-rs 0.2.9"
	}
	// Only where the version is a cause this rejection could have. Every other
	// rejection is about the file, which visudo has already said its piece about,
	// and a note on all of them sends operators after a sudo upgrade they do not
	// need. Silent where the version could not be read: a guess is worse than
	// nothing.
	if !older {
		return ""
	}
	return "\nThis host reports " + banner + ". The grant needs " + floor +
		"or newer, that being where noninteractive_auth arrived: without it `sudo -n` fails " +
		"before the PAM stack runs, so no question is put. Upgrade sudo, or install without " +
		"--allow-sudo"
}

// olderThanFloor reports whether a version banner names a release without
// noninteractive_auth: sudo before 1.9.11, sudo-rs before 0.2.9. A banner it
// cannot parse answers false, so an unrecognised sudo draws no note.
func olderThanFloor(banner string) bool {
	digits := func(s string) []int {
		var out []int
		for _, part := range strings.FieldsFunc(s, func(r rune) bool {
			return r < '0' || r > '9'
		}) {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil
			}
			out = append(out, n)
		}
		return out
	}
	fields := strings.Fields(banner)
	version := ""
	for _, field := range fields {
		if strings.ContainsAny(field, "0123456789") && strings.Contains(field, ".") {
			version = field
			break
		}
	}
	parts := digits(version)
	if len(parts) < 3 {
		return false
	}
	floor := []int{1, 9, 11}
	if bannerIsRs(banner) {
		floor = []int{0, 2, 9}
	}
	for i := range floor {
		if parts[i] != floor[i] {
			return parts[i] < floor[i]
		}
	}
	return false
}

// firstLine is what a version banner's first line says, both implementations
// printing more than one.
func firstLine(text string) string {
	head, _, _ := strings.Cut(text, "\n")
	return head
}

// RsProbe answers the question, a variable so a test can answer for a host
// whose sudo is the other one. Nothing else here is stubbed: what it returns is
// the only thing the rest of the package reads.
var RsProbe = probeRs

// probeRs reports whether this host's sudo is sudo-rs.
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
func probeRs() bool {
	for _, program := range []string{"sudo", "visudo"} {
		path, err := exec.LookPath(program)
		if err != nil {
			continue
		}
		out, err := exec.CommandContext(context.Background(), path, "-V").CombinedOutput()
		if err != nil {
			continue
		}
		return bannerIsRs(firstLine(string(out)))
	}
	return false
}

// bannerIsRs reads an implementation off a version banner.
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
func bannerIsRs(banner string) bool {
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

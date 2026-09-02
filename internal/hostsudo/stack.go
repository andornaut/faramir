package hostsudo

// Reading a PAM stack to say whether the block in it still does what it should.

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// ForeignAuthModule is the first auth line naming a module rather than pulling
// in the distribution's shared stack, or "".
//
// An `auth include system-auth` or `@include common-auth` is what a stock file
// says and is not worth a word; a `pam_duo.so` or a `pam_google_authenticator.so`
// is something somebody added to this host on purpose.
func ForeignAuthModule(body []byte) string {
	for line := range strings.Lines(string(body)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "auth") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "auth"))
		if strings.HasPrefix(rest, "include") || strings.HasPrefix(rest, "substack") {
			continue
		}
		return line
	}
	return ""
}

// BranchProblem says what is wrong with the branch in the shared stacks,
// or "". It is the whole of what selects faramir's service on a sudo-rs host, so
// a stack that lost it is a host where every escalation fails, and one that kept
// a branch it cannot reach is worse: the executor meets the password check
// below and the question is never put.
//
// /etc/pam.d/sudo is a dpkg conffile. An upgrade that installs the maintainer's
// version drops the block without saying so, which is the failure this exists to
// name.
func BranchProblem(execUser, helper string) string {
	// How many shared stacks were there to check. None at all is not a pass: on a
	// sudo-rs host the branch is the whole of what selects faramir's service, so a
	// host with nowhere to put it is one where every escalation reaches
	// /etc/pam.d/other instead.
	checked := 0
	for _, path := range hostlayout.SudoPamStacks() {
		current, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			// A launch type this distribution does not split out. Nothing selects a
			// service that is never asked for.
			continue
		}
		checked++
		if err != nil {
			return fmt.Sprintf("%s cannot be read (%v), so what decides an escalation "+
				"there went unchecked. The operator can re-run this as root", path, err)
		}
		start, _, found, err := placeBlock(current)
		switch {
		case err != nil:
			return fmt.Sprintf("%s carries one faramir marker without the other, so "+
				"what the block is cannot be read off it. Fix the markers by hand and "+
				"re-run `faramir init --allow-sudo`", path)
		case !found:
			return fmt.Sprintf("%s carries no faramir block, so this host's sudo-rs sends %s to the stock stack, "+
				"where its locked password refuses: every escalation fails. A package upgrade "+
				"replaced that file, or the install was made when the `sudo` alternatives group "+
				"pointed elsewhere. Re-run `faramir init --allow-sudo`", path, execUser)
		}
		block := string(current[start:])
		if at := strings.Index(block, PamBlockEnd); at >= 0 {
			block = block[:at]
		}
		switch {
		case !strings.Contains(block, "pam_succeed_if.so"):
			return fmt.Sprintf("%s's faramir block does not test which account is authenticating, so it applies "+
				"to every account rather than to %s alone. Re-run `faramir init --allow-sudo`",
				path, execUser)
		case execUser == "":
			return fmt.Sprintf("which account runs the executor is not known here, so "+
				"whether %s's faramir block tests for it went unchecked. Pass "+
				"--exec-user", path)
		case !strings.Contains(block, "user = "+execUser):
			return fmt.Sprintf("%s's faramir block tests for an account that is not "+
				"%s, so the executor falls through to the stock stack and every "+
				"escalation fails. Re-run `faramir init --allow-sudo`", path, execUser)
		case helper != "" && !strings.Contains(block, helper):
			return fmt.Sprintf("%s's faramir block does not exec %s, so something "+
				"other than faramir decides these escalations. Re-run "+
				"`faramir init --allow-sudo`", path, helper)
		}
		// The jump has to clear every faramir module below it. One short and it
		// lands on this block's own pam_permit, which authenticates every account
		// the branch was meant to let past.
		if problem := branchJumpProblem(path, block); problem != "" {
			return problem
		}
		if before := FirstAuthLine(current[:start]); before != "" {
			return fmt.Sprintf("%s has an auth line ahead of the faramir block (%q), "+
				"so %s meets it before the branch is reached. Re-run "+
				"`faramir init --allow-sudo`", path, before, execUser)
		}
	}
	if checked == 0 {
		return fmt.Sprintf("this host's sudo is sudo-rs, which reaches the service named `sudo` alone, and "+
			"neither %s exists to carry the stack that asks the broker: every escalation falls "+
			"to %s/other. Install sudo, then re-run `faramir init --allow-sudo`",
			strings.Join(hostlayout.SudoPamStacks(), " nor "), hostlayout.PamDir)
	}
	return ""
}

// branchJumpProblem checks the arithmetic that decides who meets what: the
// branch's `default=N` must skip every auth line after it inside the block.
//
// One short and an account that is not the executor lands on the block's own
// `sufficient pam_permit`, which authenticates it with no password. This is the
// worst thing this file can get wrong, so it is checked on a host rather than
// only against what was rendered.
func branchJumpProblem(path, block string) string {
	jump, after := -1, 0
	for line := range strings.Lines(block) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "auth") {
			continue
		}
		if jump < 0 {
			at := strings.Index(line, "default=")
			if at < 0 {
				return fmt.Sprintf("%s's faramir block does not branch on the account "+
					"at all, so it applies to everybody. Re-run `faramir init --allow-sudo`",
					path)
			}
			rest := line[at+len("default="):]
			end := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
			if end >= 0 {
				rest = rest[:end]
			}
			n, err := strconv.Atoi(rest)
			if err != nil {
				return fmt.Sprintf("%s's faramir block does not jump a number of "+
					"modules (%q). Re-run `faramir init --allow-sudo`", path, line)
			}
			jump = n
			continue
		}
		after++
	}
	if jump >= 0 && jump != after {
		return fmt.Sprintf("%s's faramir block skips %d module(s) and has %d after the branch, so an account "+
			"that is not the executor lands inside it and is authenticated without a password. "+
			"Re-run `faramir init --allow-sudo`",
			path, jump, after)
	}
	return ""
}

// FirstAuthLine is the first thing in a stack that can authenticate, or "".
// What is ahead of the block decides whether the branch is reached at all.
//
// An `@include` counts. The stock Debian and Ubuntu /etc/pam.d/sudo has no line
// beginning `auth` at all -- it authenticates with `@include common-auth` -- so
// a check that only looked for the one would report a block sitting below the
// other as correctly placed, on the file this is most likely to be reading.
func FirstAuthLine(body []byte) string {
	for line := range strings.Lines(string(body)) {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "auth"):
			return line
		case strings.HasPrefix(line, "@include"):
			// Pulls in every type, auth among them.
			return line
		}
	}
	return ""
}

// FirstExistingStack is the shared stack a diagnosis should read, which is the
// first one this host actually has. Falls back to the first name so a message
// about a host with neither still names a path.
func FirstExistingStack() string {
	for _, path := range hostlayout.SudoPamStacks() {
		if hostfs.Exists(path) {
			return path
		}
	}
	return hostlayout.SudoPamStacks()[0]
}

// StackProblem names what is wrong with the authentication stack, or "".
// Two things decide whether it gates anything. `requisite` on the helper: with
// `sufficient` a refusal is not fatal, the stack falls through to whatever
// permits below, and every escalation is granted without asking. And
// `seteuid`: without it pam_exec runs the helper with the real uid, which under
// setuid sudo is the executor's own, and the broker answers the escalate op to
// root alone.
func StackProblem(body, helper string) string {
	// Position matters as much as the helper line itself: an auth entry ahead of
	// it authenticates before the broker is asked, and the requisite below then
	// gates nothing. Ahead of the helper only the sudo-rs block's own branch may
	// stand, a pam_succeed_if under a [success=ok ...] spec; the sudo-rs path
	// holds what is outside the block to the same rule with firstAuthLine.
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "@include") {
			return "an @include ahead of the helper pulls in an auth stack that " +
				"answers before the broker is asked (" + line + "). Re-run " +
				"`faramir init --allow-sudo`"
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "auth" {
			continue
		}
		control, rest := authLine(fields)
		module := ""
		if len(rest) > 0 {
			module = rest[0]
		}
		if module != "pam_exec.so" {
			if module == "pam_succeed_if.so" && strings.HasPrefix(control, "[success=ok ") {
				continue
			}
			return "an auth line ahead of the helper answers before the broker is " +
				"asked (" + line + "). Re-run `faramir init --allow-sudo`"
		}
		// The helper line, each word matched as the field it is rather than as a
		// substring anything on the line could carry.
		switch {
		case control != "requisite":
			return "the helper is not `requisite`, so a refusal falls through to whatever permits " +
				"below and every escalation is granted without asking. Re-run `faramir init " +
				"--allow-sudo`"
		case !slices.Contains(rest, "seteuid"):
			return "the helper runs without `seteuid`, so pam_exec runs it as the executor rather " +
				"than root, and the broker answers the escalate op to root alone: every " +
				"escalation fails. Re-run `faramir init --allow-sudo`"
		case helper != "" && !slices.Contains(rest, helper):
			return "the helper is not " + helper + ", so something other than faramir " +
				"decides these escalations"
		}
		return ""
	}
	return "no pam_exec auth line, so nothing asks the broker and whatever else " +
		"is in this file decides. Re-run `faramir init --allow-sudo`"
}

// authLine splits one auth entry into its control field, a bracketed spec
// kept whole, and the module with its arguments after it.
func authLine(fields []string) (control string, rest []string) {
	if len(fields) < 2 {
		return "", nil
	}
	i := 2
	if strings.HasPrefix(fields[1], "[") {
		for i < len(fields) && !strings.HasSuffix(fields[i-1], "]") {
			i++
		}
	}
	return strings.Join(fields[1:i], " "), fields[i:]
}

// PermissiveAuth reports whether a stack authenticates without asking: a
// pam_permit with nothing that can refuse ahead of it.
func PermissiveAuth(body string) bool {
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "auth") {
			continue
		}
		if strings.Contains(line, "pam_permit.so") {
			return true
		}
		// Anything else in the auth stack (a unix check, a deny, an include) means
		// the fallback is not a free pass.
		return false
	}
	return false
}

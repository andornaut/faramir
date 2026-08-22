// Package version holds the one version string every binary reports. Its own
// package, so reaching it does not link the redactor, the executor and the
// keeper client into the CLI and the MCP server.
package version

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// Version is the build version reported by the version command. A var rather
// than a const because the linker stamps it: -X takes a variable and silently
// does nothing to a constant. The ldflags in .goreleaser.yaml set it for a
// tagged build, and init below decides what an unstamped one reports.
var Version = "dev"

// Build is which build of an unstamped binary this is, and "" for one whose
// version already names it. Every build that reports "dev" reports the same
// "dev", so two of them compare equal and the version check that exists to
// catch daemons left on the binary they were started from never fires. The
// revision is what separates them: the dev release is a moving tag repointed
// per commit, so two dev builds are two commits.
//
// Not folded into Version, which would be a different and worse change:
// Mismatch refuses a caller whose version is not this binary's, so a Version
// that changed per build would refuse every running MCP server and agent on
// every rebuild rather than at a release.
var Build = ""

// A binary the linker did not stamp can still know what it was built from:
// `go install <module>@v1.2.3` records the version and records no VCS settings,
// having built from the module cache rather than from a checkout. A build made
// from a working tree records vcs.revision, and is a local build whatever the
// tree is sitting on, so it keeps "dev" rather than claiming the tag under it.
func init() {
	if Version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, setting := range info.Settings {
		if strings.HasPrefix(setting.Key, "vcs") {
			Build = buildID(info.Settings)
			return
		}
	}
	if v := releaseVersion(info.Main.Version); v != "" {
		Version = v
	}
}

// buildID is the revision, short enough to read in a report, with a marker for
// a tree that carried edits. Two builds off one commit with different edits are
// still one id: what the toolchain records cannot tell them apart, and this
// says "modified" rather than implying it can.
func buildID(settings []debug.BuildSetting) string {
	var revision, modified string
	for _, setting := range settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			if setting.Value == "true" {
				modified = "-modified"
			}
		}
	}
	if revision == "" {
		return ""
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	return revision + modified
}

// releaseVersion returns what to report for a version the module system
// recorded, or "" where that version does not name a release. A pseudo-version
// carries a timestamp and a revision, a build off a modified tree carries
// +dirty, and a module built outside the module system reports "(devel)"; none
// of those names a release, and a binary reporting one would be claiming to be
// something it is not.
//
// The leading v is dropped so that both halves spell one release the same way:
// the stamp is goreleaser's {{.Version}}, which is the tag without it, and the
// module system records the tag with it. Reporting 1.2.3 from the published
// archive and v1.2.3 from `go install` would make the version depend on how the
// binary arrived.
func releaseVersion(v string) string {
	digits, found := strings.CutPrefix(v, "v")
	if !found {
		return ""
	}
	parts := strings.Split(digits, ".")
	if len(parts) != 3 {
		return ""
	}
	for _, part := range parts {
		if part == "" || strings.TrimLeft(part, "0123456789") != "" {
			return ""
		}
	}
	return digits
}

// Mismatch reports why a caller's version is not this binary's, and "" where it
// is. Every request on every socket names the version of the binary that sent
// it, and a difference is refused rather than tolerated: a caller from another
// release is a process that outlived the install which replaced the binary
// under it, so the alternative is failing later on whichever op or field
// changed in between, which says nothing about why.
//
// Lives here rather than in the protocol package because all three sockets make
// the same check and say the same thing about it.
func Mismatch(caller string) string {
	if caller == Version {
		return ""
	}
	named := "faramir " + caller
	if caller == "" {
		named = "no version"
	}
	return fmt.Sprintf("the caller names %s and this is faramir %s: restart it. "+
		"An MCP server is a child of the coding agent, so it is reconnected there "+
		"rather than restarted on its own", named, Version)
}

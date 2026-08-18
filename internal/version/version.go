// Package version holds the one version string every binary reports.  Its own
// package, so reaching it does not link the redactor, the executor and the
// keeper client into the CLI and the MCP server.
package version

// Version is the build version reported by --version and by the status op. A
// var rather than a const because the linker stamps it: -X takes a variable and
// silently does nothing to a constant. The ldflags in .goreleaser.yaml set it
// for a tagged build, and every other build, the rolling dev archive included,
// reports "dev".
var Version = "dev"

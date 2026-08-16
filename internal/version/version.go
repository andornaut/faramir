// Package version holds the one version string every binary reports.  Its own
// package, so reaching the constant does not link the redactor, the executor and
// the keeper client into the CLI and the MCP server.
package version

// Version is the build version reported by --version and by the status op.
const Version = "0.1.2"

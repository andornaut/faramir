// Package version holds the one version string every binary reports.
//
// It is its own package because the CLI and the MCP server report it too, and
// importing the broker to reach a constant would link the redactor, the
// executor and the keeper client into both of them.
package version

// Version is the build version reported by --version and by the status op.
const Version = "0.1.0"

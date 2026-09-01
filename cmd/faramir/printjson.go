package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// printJSON writes a record, a list of them or a report to stdout as indented
// JSON: the machine-readable form of what the text listing shows. One function
// for every command that takes --json, so a marshal that fails is an exit code
// in each rather than an empty stdout in some of them: under --json the
// document is the whole answer, and exiting 0 having printed nothing reads to a
// configuration manager as a host that needed no work.
//
// label names the subcommand for the error, the caller having it and this not.
func printJSON(label string, v any) int {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	fmt.Println(string(body))
	return 0
}

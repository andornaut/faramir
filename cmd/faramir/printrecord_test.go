package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// renderRecord is printRecord's output, captured.  The command writes to stdout
// directly, this being what an operator reads.
func renderRecord(t *testing.T, line string, paint palette) string {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	done := make(chan string)
	go func() {
		body, _ := io.ReadAll(read)
		done <- string(body)
	}()
	printRecord(record, paint)
	os.Stdout = original
	_ = write.Close()
	return <-done
}

// The detail view is every field a record can carry, in one rendering: the
// labelled rows, the two list fields, the redaction counts and the output.
const detailFixture = `{"log_id":"2026-08-08T20:15:03Z-a91f000007","op":"exec",` +
	`"peer":{"uid":0,"pid":4242},"cmd":["ansible-playbook","site.yml"],` +
	`"cwd":"/srv/project","exit_code":0,"duration_sec":1.5,` +
	`"env_refs":["db/password","api/token"],"from":["age1aaa"],"to":["age1bbb"],` +
	`"redactions":[{"token":"FARAMIR_REDACTED_1","count":3},` +
	`{"token":"FARAMIR_REDACTED_2","count":1}],` +
	`"output":"ok: [host.example.com]\nchanged=0\n","output_truncated":true}`

func TestPrintRecordRendersEveryField(t *testing.T) {
	got := renderRecord(t, detailFixture, plain(t))
	for _, want := range []string{
		"id         2026-08-08T20:15:03Z-a91f000007",
		"caller     root (uid 0), pid 4242",
		"cwd        /srv/project",
		"refs       db/password, api/token",
		"from       age1aaa",
		"to         age1bbb",
		"redacted   FARAMIR_REDACTED_1×3, FARAMIR_REDACTED_2×1",
		"output",
		"    ok: [host.example.com]",
		"    changed=0",
		"[truncated at [audit] max_record_bytes]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the detail view does not carry %q:\n%s", want, got)
		}
	}
}

// A field the record does not have prints no row at all: a labelled row with
// nothing after it reads as a value that is empty rather than one that is
// absent.
func TestPrintRecordOmitsAbsentFields(t *testing.T) {
	got := renderRecord(t, `{"log_id":"x","op":"redact","input_bytes":2048}`, plain(t))
	for _, absent := range []string{"caller", "cwd", "refs", "from", "to", "redacted", "output"} {
		if strings.Contains(got, absent) {
			t.Errorf("a row was printed for the absent %q field:\n%s", absent, got)
		}
	}
}

// Colour on, the same rows still carry their values: the emptiness test that
// decides whether a row prints has to see the value rather than the escapes
// around it.
func TestPrintRecordWithColourPrintsTheSameRows(t *testing.T) {
	colour, mono := renderRecord(t, detailFixture, always(t)), renderRecord(t, detailFixture, plain(t))
	if strings.Count(colour, "\n") != strings.Count(mono, "\n") {
		t.Errorf("colour changed how many rows print:\n%s\nvs\n%s", colour, mono)
	}
	if !strings.Contains(colour, "\x1b[") {
		t.Error("the colour palette rendered no escapes, so this asserts nothing")
	}
}

// Rendered rather than printed: cwd, error and outcome carry text the audited
// account chose, and an escape in one of them rewrites the operator's terminal.
func TestPrintRecordRendersTerminalControlsInCallerText(t *testing.T) {
	line, err := json.Marshal(map[string]any{
		"log_id": "x", "op": "exec", "cwd": "/srv\x1b[2Jwiped",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := renderRecord(t, string(line), plain(t))
	if strings.Contains(got, "\x1b[2J") {
		t.Errorf("an escape from the record reached the terminal: %q", got)
	}
	fmt.Fprint(io.Discard, got)
}

package auditview

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/termui"
	"github.com/andornaut/faramir/internal/termuitest"
	"github.com/andornaut/faramir/internal/testio"
)

// renderRecord is printRecord's output, captured. The command writes to stdout
// directly, this being what an operator reads.
func renderRecord(t *testing.T, line string, paint termui.Palette) string {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatal(err)
	}
	out, _ := testio.CaptureStdout(t, func() int { PrintRecord(record, paint); return 0 })
	return out
}

// The detail view is every field a record can carry, in one rendering: the
// labelled rows, the two list fields, the refs object, the redaction counts and
// the output. Every field is spelled the way the writer spells it, env_refs
// included -- internal/broker records NAME -> ref, not a list of refs.
const detailFixture = `{"log_id":"w5vq7dbf000007","op":"run",` +
	`"peer":{"uid":0,"pid":4242},"cmd":["ansible-playbook","site.yml"],` +
	`"argv0_path":"/usr/bin/ansible-playbook",` +
	`"cwd":"/srv/project","exit_code":0,"duration_sec":1.5,` +
	`"env_refs":{"PW":"db/password","TOKEN":"api/token"},` +
	`"from":["age1aaa"],"to":["age1bbb"],"record_reduced":true,` +
	`"redactions":[{"token":"FARAMIR_REDACTED_1","count":3},` +
	`{"token":"FARAMIR_REDACTED_2","count":1}],` +
	`"output":"ok: [host.example.com]\nchanged=0\n","output_truncated":true}`

func TestPrintRecordRendersEveryField(t *testing.T) {
	got := renderRecord(t, detailFixture, termuitest.Plain(t))
	for _, want := range []string{
		// The id leads the summary line rather than being a field of its own.
		"w5vq7dbf000007",
		"reduced    fields were cut to fit the record cap",
		"caller     root (uid 0), pid 4242",
		"cwd        /srv/project",
		"program    /usr/bin/ansible-playbook",
		"refs       PW=db/password, TOKEN=api/token",
		"from       age1aaa",
		"to         age1bbb",
		"redacted   FARAMIR_REDACTED_1×3, FARAMIR_REDACTED_2×1",
		"output",
		"    ok: [host.example.com]",
		"    changed=0",
		"[truncated at the record cap]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the detail view does not carry %q:\n%s", want, got)
		}
	}
}

// The refs row is the one field whose shape a reader can get wrong silently: a
// list where the record holds an object prints nothing at all, and a record
// with no refs prints nothing either, so the view looks the same both ways.
func TestRefsRowReadsTheShapeTheBrokerWrites(t *testing.T) {
	got := renderRecord(t, `{"log_id":"x","op":"run",`+
		`"env_refs":{"TOKEN":"api/token","PW":"db/password"}}`, termuitest.Plain(t))
	// Sorted by variable name rather than by whatever the map iterated to first.
	if !strings.Contains(got, "refs       PW=db/password, TOKEN=api/token") {
		t.Errorf("the refs row is not the record's pairs in order:\n%s", got)
	}
}

// A field the record does not have prints no row at all: a labelled row with
// nothing after it reads as a value that is empty rather than one that is
// absent.
func TestPrintRecordOmitsAbsentFields(t *testing.T) {
	got := renderRecord(t, `{"log_id":"x","op":"redact","input_bytes":2048}`, termuitest.Plain(t))
	for _, absent := range []string{
		"caller", "cwd", "program", "reason", "reduced",
		"refs", "from", "to", "redacted", "output",
	} {
		if strings.Contains(got, absent) {
			t.Errorf("a row was printed for the absent %q field:\n%s", absent, got)
		}
	}
}

// Colour on, the same rows still carry their values: the emptiness test that
// decides whether a row prints has to see the value rather than the escapes
// around it.
func TestPrintRecordWithColourPrintsTheSameRows(t *testing.T) {
	colour, mono := renderRecord(t, detailFixture, termuitest.Always(t)), renderRecord(t, detailFixture, termuitest.Plain(t))
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
		"log_id": "x", "op": "run", "cwd": "/srv\x1b[2Jwiped",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := renderRecord(t, string(line), termuitest.Plain(t))
	if strings.Contains(got, "\x1b[2J") {
		t.Errorf("an escape from the record reached the terminal: %q", got)
	}
}

// Counts, never values.
func TestRedactionCountsRenderTokensAndCounts(t *testing.T) {
	got := redactionCounts(rec(t,
		`{"log_id":"x","redactions":[{"token":"«SECRET:a»","count":2},{"token":"«SECRET:b»","count":1}]}`))
	if got != "«SECRET:a»×2, «SECRET:b»×1" {
		t.Errorf("redactionCounts = %q", got)
	}
}

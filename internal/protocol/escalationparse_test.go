package protocol

import (
	"strings"
	"testing"
)

// What the broker accepts as an escalation request. The pids are the whole of
// what identifies the run a sudo belongs to, so a request that named the wrong
// kind of number would have the broker asking the executor about something that
// is not a process: 0 and negatives are how kill() names a process group, and
// pid 1 is init, which no brokered command is.
func TestTheProcsOfAnEscalateAreEachAPid(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want []int // nil means the request must be refused
	}{
		{"a pid", `{"op":"escalate","procs":[2]}`, []int{2}},
		{"several", `{"op":"escalate","procs":[2,3,4000]}`, []int{2, 3, 4000}},
		{"no procs at all", `{"op":"escalate"}`, nil},
		{"an empty list", `{"op":"escalate","procs":[]}`, nil},
		{"null", `{"op":"escalate","procs":null}`, nil},
		{"not a list", `{"op":"escalate","procs":2}`, nil},
		// The three a pid is not.
		{"a process group", `{"op":"escalate","procs":[0]}`, nil},
		{"a negative process group", `{"op":"escalate","procs":[-1]}`, nil},
		{"init", `{"op":"escalate","procs":[1]}`, nil},
		// JSON has one number type, so an integral value is asked for rather
		// than assumed.
		{"a fraction", `{"op":"escalate","procs":[2.5]}`, nil},
		{"a pid as a string", `{"op":"escalate","procs":["2"]}`, nil},
		{"a boolean", `{"op":"escalate","procs":[true]}`, nil},
		// One bad entry refuses the request rather than the entry: a partial
		// ancestry names a different run from the one that asked.
		{"one bad entry among good ones", `{"op":"escalate","procs":[2,0,4]}`, nil},
		{"a bad entry last", `{"op":"escalate","procs":[2,3,1]}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := parse(t, tc.body)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("accepted, and procs = %v", req.Procs)
				}
				if !strings.Contains(err.Error(), "procs") {
					t.Errorf("the refusal does not name the field: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if len(req.Procs) != len(tc.want) {
				t.Fatalf("procs = %v, want %v", req.Procs, tc.want)
			}
			for i, pid := range tc.want {
				if req.Procs[i] != pid {
					t.Errorf("procs[%d] = %d, want %d", i, req.Procs[i], pid)
				}
			}
		})
	}
}

// The two durations any op may carry. Absent and null are the ordinary case and
// leave the broker's own default standing; a value that is there has to be one
// the broker can act on, or a watcher blocks for a length nobody chose.
func TestTheWaitAndTimeoutAreCheckedWhereTheyAreGiven(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		refused bool
		wait    int
		timeout int
	}{
		{name: "neither given", body: `{"op":"status"}`},
		{name: "both null", body: `{"op":"status","wait_sec":null,"timeout_sec":null}`},
		{name: "a wait of zero", body: `{"op":"status","wait_sec":0}`},
		{name: "a wait", body: `{"op":"status","wait_sec":30}`, wait: 30},
		{name: "a negative wait", body: `{"op":"status","wait_sec":-1}`, refused: true},
		{name: "a wait as a string", body: `{"op":"status","wait_sec":"30"}`, refused: true},
		{name: "a fractional wait", body: `{"op":"status","wait_sec":1.5}`, refused: true},
		{name: "a boolean wait", body: `{"op":"status","wait_sec":true}`, refused: true},
		// The timeout is the other bound: zero is not a duration to run for.
		{name: "a timeout", body: `{"op":"status","timeout_sec":30}`, timeout: 30},
		{name: "a timeout of zero", body: `{"op":"status","timeout_sec":0}`, refused: true},
		{name: "a negative timeout", body: `{"op":"status","timeout_sec":-1}`, refused: true},
		{name: "a fractional timeout", body: `{"op":"status","timeout_sec":1.5}`, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := parse(t, tc.body)
			if tc.refused {
				if err == nil {
					t.Fatalf("accepted: wait=%d timeout=%d", req.WaitSec, req.TimeoutSec)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if req.WaitSec != tc.wait {
				t.Errorf("wait_sec = %d, want %d", req.WaitSec, tc.wait)
			}
			if req.TimeoutSec != tc.timeout {
				t.Errorf("timeout_sec = %d, want %d", req.TimeoutSec, tc.timeout)
			}
		})
	}
}

// An answer names the question it answers, and says yes only where it says yes.
// Anything else is a rejection: a malformed answer that read as an approval
// would grant root on a field the broker could not parse.
func TestAnAnswerNamesItsQuestionAndApprovesOnlyOnTrue(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		refused bool
		approve bool
	}{
		{name: "a yes", body: `{"op":"answer","id":"9f2a1c","approved":true}`, approve: true},
		{name: "a no", body: `{"op":"answer","id":"9f2a1c","approved":false}`},
		// Everything that is not the boolean true is a rejection rather than an
		// error: the answer arrived, and what it did not say is no.
		{name: "no approved field", body: `{"op":"answer","id":"9f2a1c"}`},
		{name: "approved as a string", body: `{"op":"answer","id":"9f2a1c","approved":"yes"}`},
		{name: "approved as a number", body: `{"op":"answer","id":"9f2a1c","approved":1}`},
		{name: "approved null", body: `{"op":"answer","id":"9f2a1c","approved":null}`},
		// The id is what the answer is spent on, so a missing one is refused
		// rather than defaulted.
		{name: "no id", body: `{"op":"answer","approved":true}`, refused: true},
		{name: "an empty id", body: `{"op":"answer","id":"","approved":true}`, refused: true},
		{name: "an id that is not a string", body: `{"op":"answer","id":42}`, refused: true},
		{name: "a null id", body: `{"op":"answer","id":null}`, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := parse(t, tc.body)
			if tc.refused {
				if err == nil {
					t.Fatal("accepted an answer that names no question")
				}
				if !strings.Contains(err.Error(), "id") {
					t.Errorf("the refusal does not name the field: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if req.Approve != tc.approve {
				t.Errorf("approve = %v, want %v", req.Approve, tc.approve)
			}
		})
	}
}

// The run a watcher is waiting to hear the end of. Absent is the ordinary case,
// so it is not an error; a value that is there has to name a record.
func TestTheAwaitedLogIDIsCheckedOnlyWhereItIsGiven(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		refused bool
		want    string
	}{
		{name: "absent", body: `{"op":"escalations"}`},
		{name: "null", body: `{"op":"escalations","await_log_id":null}`},
		{name: "a record", body: `{"op":"escalations","await_log_id":"w5vq7dbf000119"}`,
			want: "w5vq7dbf000119"},
		{name: "not a string", body: `{"op":"escalations","await_log_id":42}`, refused: true},
		{name: "a list", body: `{"op":"escalations","await_log_id":["x"]}`, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := parse(t, tc.body)
			if tc.refused {
				if err == nil {
					t.Fatalf("accepted, and await_log_id = %q", req.AwaitLogID)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if req.AwaitLogID != tc.want {
				t.Errorf("await_log_id = %q, want %q", req.AwaitLogID, tc.want)
			}
		})
	}
}

// Every shape of bad timeout gets the one refusal, which names wholeness and
// magnitude both: a fraction and a float past int64 arrive indistinguishable
// once decoded.
func TestARefusedTimeoutNamesBothCorrections(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"a fraction", `{"op":"status","timeout_sec":1.5}`},
		{"a small fraction", `{"op":"status","timeout_sec":0.5}`},
		{"past int64", `{"op":"status","timeout_sec":1e20}`},
		{"far past int64", `{"op":"status","timeout_sec":1e300}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, tc.body)
			if err == nil {
				t.Fatal("accepted")
			}
			for _, want := range []string{"whole number of seconds", "too large"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal is %q, want it to say %q", err, want)
				}
			}
		})
	}
}

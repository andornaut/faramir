package auditview

// Turning a record's raw JSON values into what a reader sees: the timestamps,
// the sizes, and the scalars a map holds as any.

import (
	"fmt"
	"os/user"
	"strconv"
	"time"
)

// dateLayout is the day heading a run of records sits under. The zone is in
// the header because the times below are local and the log_id beside them is
// UTC.
const dateLayout = "2006-01-02 MST"

// startedAt is when the record's subject happened: started_at where the record
// has one, which is the child's fork rather than the moment the line was
// written, and otherwise the `at` every other record carries.
func startedAt(record map[string]any) time.Time {
	for _, field := range []string{"started_at", "at"} {
		if seconds, ok := num(record, field); ok {
			return time.Unix(int64(seconds), 0)
		}
	}
	return time.Time{}
}

// clockTime is local, the log being read against what somebody remembers doing.
func clockTime(record map[string]any) string {
	at := startedAt(record)
	if at.IsZero() {
		return "        "
	}
	return at.Format("15:04:05")
}

// matchesID compares the log_id as it is printed, so what is on screen pastes
// back.
func matchesID(record map[string]any, want string) bool {
	return str(record, "log_id") == want
}

// describePeer renders the caller from pid, uid and gid, resolving the uid to a
// name where the account still exists.
func describePeer(record map[string]any) string {
	fields, ok := record["peer"].(map[string]any)
	if !ok {
		return ""
	}
	uid, _ := num(fields, "uid")
	pid, _ := num(fields, "pid")
	who := fmt.Sprintf("uid %d", int(uid))
	if account, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		who = fmt.Sprintf("%s (uid %d)", account.Username, int(uid))
	}
	return fmt.Sprintf("%s, pid %d", who, int(pid))
}

// humanBytes keeps a size to three significant figures; this column is for
// judging scale.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value, exponent := float64(n)/unit, 0
	for value >= unit && exponent < 3 {
		value /= unit
		exponent++
	}
	return fmt.Sprintf("%.1f %ciB", value, "KMGT"[exponent])
}

func str(record map[string]any, key string) string {
	value, _ := record[key].(string)
	return value
}

// num is a recorded number and whether the field was there. encoding/json
// returns every number as a float64, and the callers here have to tell an
// absent exit code from one of zero.
func num(record map[string]any, key string) (float64, bool) {
	value, ok := record[key].(float64)
	return value, ok
}

// boolean is a recorded flag and whether the field was there. Not `flag`,
// which is a standard library package this file's callers use.
func boolean(record map[string]any, key string) (bool, bool) {
	value, ok := record[key].(bool)
	return value, ok
}

func list(record map[string]any, key string) []string {
	entries, ok := record[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if text, ok := entry.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

package execclient

import (
	"errors"
	"fmt"
	"testing"

	"github.com/andornaut/faramir/internal/execserver"
)

// The output path's byte handling, tested directly. Run() needs a PTY and a
// delegated cgroup and skips without one; these need neither, so the rune and
// truncation rules are checked on every host.

// Anything not valid on its own is held back for the next read, whether or not
// more bytes could complete it. Run flushes the remainder after the loop, so
// holding back a byte that never becomes valid costs a read, not output.
func TestDecodeUTF8HoldsBackWhatIsNotYetValid(t *testing.T) {
	for _, tc := range []struct {
		name          string
		b             string
		wantText      string
		wantRemainder string
	}{
		{"all ascii", "hello", "hello", ""},
		{"empty", "", "", ""},
		{"a whole multi-byte rune", "hé", "hé", ""},
		{"a two-byte rune cut in half", "h\xc3", "h", "\xc3"},
		{"a three-byte rune cut short", "a\xe2\x82", "a", "\xe2\x82"},
		{"a four-byte rune cut short", "a\xf0\x9d\x84", "a", "\xf0\x9d\x84"},
		{"a trailing byte that cannot start a rune is held back", "a\xff", "a", "\xff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, rest := decodeUTF8([]byte(tc.b))
			if text != tc.wantText || string(rest) != tc.wantRemainder {
				t.Errorf("decodeUTF8(%q) = (%q, %q), want (%q, %q)",
					tc.b, text, rest, tc.wantText, tc.wantRemainder)
			}
		})
	}
}

// Nothing may be lost between the two returns: the remainder is carried into the
// next read, so a byte dropped here never reaches the output at all.
func TestDecodeUTF8LosesNothing(t *testing.T) {
	const full = "aé€𝄞\xffz"
	for i := 0; i <= len(full); i++ {
		text, rest := decodeUTF8([]byte(full[:i]))
		if got := text + string(rest); got != full[:i] {
			t.Errorf("decodeUTF8(%q) round-trips to %q", full[:i], got)
		}
	}
}

func TestIsEIORecognisesAClosedTerminal(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not EIO", nil, false},
		{"the read error a closed PTY gives", errors.New("read /dev/ptmx: input/output error"), true},
		{"any other error", errors.New("permission denied"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isEIO(tc.err); got != tc.want {
				t.Errorf("isEIO(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRound3RoundsToMilliseconds(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want float64
	}{
		{0, 0},
		{1.0004, 1.0},
		{1.0005, 1.001},
		{1.9999, 2.0},
		{12.3456, 12.346},
	} {
		t.Run(fmt.Sprint(tc.in), func(t *testing.T) {
			if got := round3(tc.in); got != tc.want {
				t.Errorf("round3(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// exitStatus is reached only after the command ran and its output was
// collected. A missing or late executor status must not discard that: it
// becomes a kill code, never a fabricated success, and never an error that
// reads as a run that never happened.
func TestExitStatusPreservesAFinishedRun(t *testing.T) {
	if code, timedOut, unknown := exitStatus(&execserver.ChildResult{ExitCode: 42}, nil, false); code != 42 || timedOut || unknown {
		t.Errorf("reported status: code=%d timedOut=%v unknown=%v, want 42/false/false", code, timedOut, unknown)
	}
	// The whole budget elapsed with no status: the run overran the backstop and
	// was killed, which is a timeout.
	if code, timedOut, unknown := exitStatus(nil, errors.New("executor closed the connection"), true); code != 128+9 || !timedOut || unknown {
		t.Errorf("deadline-passed status: code=%d timedOut=%v unknown=%v, want 137/true/false", code, timedOut, unknown)
	}
	// The executor vanished before the deadline while the command had already
	// run: the status is unknowable, marked as such, output still returned.
	if code, timedOut, unknown := exitStatus(nil, errors.New("executor restarted"), false); code != 128+9 || timedOut || !unknown {
		t.Errorf("lost-status status: code=%d timedOut=%v unknown=%v, want 137/false/true", code, timedOut, unknown)
	}
}

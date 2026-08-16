package e2e

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// End-to-end adversarial probes: real broker, real executor, real PTY, real
// streaming redactor, real bash child.  Each case emits a transformed form of
// $ROUTER_PW and asserts whether that form survives to the caller; a survivor
// is a secret the model could recover.
//
// Every transform is bash builtins only (printf, parameter slicing), so each is
// the kind of script an ordinary task or a lightly-nudged agent runs.
//
// Both directions are asserted, so a case documented as out of scope that
// starts being caught fails here too, which is the signal to move it
// deliberately rather than to leave the assertion unmade.
func TestAdversarialE2E(t *testing.T) {
	h := newHarness(t)

	for _, c := range []struct {
		name string
		// script prints a transform of $ROUTER_PW; needle is the form to look
		// for in what comes back.
		script  string
		needle  string
		covered bool
		// rejoinNL strips newlines before looking, a model trivially rejoining
		// a value the tool wrapped across lines.
		rejoinNL bool
	}{
		{
			name:    "base64",
			script:  `printf '%s' "$ROUTER_PW" | base64`,
			needle:  base64.StdEncoding.EncodeToString([]byte(routerPassword)),
			covered: true,
		},
		{
			name:    "hex via printf, the bytes openssl, xxd, od and hexdump emit",
			script:  hexScript,
			needle:  hex.EncodeToString([]byte(routerPassword)),
			covered: true,
		},
		{
			name:     "raw value wrapped every 8 columns, as fold, fmt and openssl -text do",
			script:   `s="$ROUTER_PW"; for ((i=0;i<${#s};i+=8)); do printf '%s\n' "${s:$i:8}"; done`,
			needle:   routerPassword,
			rejoinNL: true,
			covered:  true,
		},
		{
			name:    "rev",
			script:  `printf '%s' "$ROUTER_PW" | rev`,
			needle:  reverseStr(routerPassword),
			covered: false,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := h.runBash(t, c.script)
			if r.Error != nil {
				t.Fatalf("broker error: %v", r.Error)
			}
			haystack := r.Output
			if c.rejoinNL {
				haystack = strings.NewReplacer("\n", "", "\r", "").Replace(haystack)
			}
			switch leaked := strings.Contains(haystack, c.needle); {
			case c.covered && leaked:
				t.Errorf("the secret form survived redaction; output=%q", r.Output)
			case !c.covered && !leaked:
				t.Errorf("this form is now covered, which is an improvement rather "+
					"than a regression: mark it covered here and say so in "+
					"docs/redaction.md; output=%q", r.Output)
			}
		})
	}
}

// hexScript prints $ROUTER_PW as lower-case hex using bash builtins alone.
const hexScript = `s="$ROUTER_PW"; for ((i=0;i<${#s};i++)); do printf '%02x' "'${s:$i:1}"; done; echo`

// A command killed at its timeout still had output before it hung, and the
// executor flushes the redactor on every exit path including the abort, so no
// buffered raw output escapes when the child is cut short.
func TestOutputPrintedBeforeATimeoutComesBackRedacted(t *testing.T) {
	h := newHarness(t)

	r := h.call(t, map[string]any{
		"op": "exec",
		"cmd": []any{"bash", "-lc",
			`printf 'TOK=%s\n' "$ROUTER_PW"; ` + hexScript + `; sleep 30`},
		"env_refs":    map[string]any{"ROUTER_PW": "secret://home/router/admin"},
		"timeout_sec": 1,
	})
	if r.Error != nil {
		t.Fatalf("broker error: %v", r.Error)
	}
	if !strings.Contains(r.Output, token) {
		t.Errorf("the printed secret did not come back as a token; output=%q", r.Output)
	}
	if !strings.Contains(r.Output, "timed out") {
		t.Errorf("no timeout notice, so the kill path was never taken; output=%q", r.Output)
	}
	if strings.Contains(r.Output, routerPassword) {
		t.Errorf("RAW SECRET LEAKED on the timeout path: %q", r.Output)
	}
	if hx := hex.EncodeToString([]byte(routerPassword)); strings.Contains(r.Output, hx) {
		t.Errorf("HEX SECRET LEAKED on the timeout path: %q", r.Output)
	}
}

func reverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

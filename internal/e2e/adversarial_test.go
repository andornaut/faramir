package e2e

import (
	"fmt"
	"strings"
	"testing"
)

// End-to-end adversarial probes: real broker, real executor, real PTY, real
// streaming redactor, real bash child. The secret is `routerPassword`
// (= "hunter2-correct-horse-battery"), injected as $ROUTER_PW. Each case emits
// a transformed form of the secret and we check whether that form survives to
// the caller. A survivor means the model would have seen a recoverable secret.
//
// Every transform here is done with bash builtins only (printf, parameter
// slicing) -- no exotic tools -- so each is a plain shell script, the kind an
// ordinary task or a lightly-nudged agent runs.

func recoverableHexLower(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		fmt.Fprintf(&b, "%02x", c)
	}
	return b.String()
}

func TestAdversarialE2E(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		name       string
		kind       string
		script     string // bash, prints a transform of $ROUTER_PW
		needle     string // the form we expect to find if it leaked
		rejoinNL   bool   // strip newlines before checking (line-wrap case)
		wantRedact bool   // true = SHOULD be caught (control / claimed-covered)
	}{
		{
			name:       "base64 (control: claimed covered)",
			kind:       "ACCIDENTAL",
			script:     `printf '%s' "$ROUTER_PW" | base64`,
			needle:     b64(routerPassword),
			wantRedact: true,
		},
		{
			name:       "hex via printf (openssl/xxd/od/hexdump emit identical bytes)",
			kind:       "ACCIDENTAL",
			script:     `s="$ROUTER_PW"; for ((i=0;i<${#s};i++)); do printf '%02x' "'${s:$i:1}"; done; echo`,
			needle:     recoverableHexLower(routerPassword),
			wantRedact: true,
		},
		{
			name:       "raw value line-wrapped every 8 cols (fold/fmt/openssl -text)",
			kind:       "ACCIDENTAL",
			script:     `s="$ROUTER_PW"; for ((i=0;i<${#s};i+=8)); do printf '%s\n' "${s:$i:8}"; done`,
			needle:     routerPassword, // present once newlines are removed
			rejoinNL:   true,
			wantRedact: true,
		},
		{
			name:       "rev (documented Not-prevented)",
			kind:       "ADVERSARIAL",
			script:     `printf '%s' "$ROUTER_PW" | rev`,
			needle:     reverseStr(routerPassword),
			wantRedact: false,
		},
	}

	for _, c := range cases {
		r := h.runBash(t, c.script)
		if r.Error != nil {
			t.Fatalf("%s: broker error: %v", c.name, r.Error)
		}
		out := r.Output

		hay := out
		if c.rejoinNL {
			// The secret is present split by newlines; a model trivially rejoins.
			hay = strings.ReplaceAll(strings.ReplaceAll(out, "\n", ""), "\r", "")
		}
		leaked := strings.Contains(hay, c.needle)

		result := "redacted"
		if leaked {
			result = ">>> LEAKED <<<"
		}
		t.Logf("%-58s %-11s %s", c.name, c.kind, result)

		// Both directions, so every case can fail.  wantRedact=false pins a
		// boundary the design documents as out of scope rather than skipping the
		// assertion: a case that stops leaking is an improvement to record, not a
		// result to leave unchecked.
		switch {
		case c.wantRedact && leaked:
			t.Errorf("%s: expected redaction but the secret form leaked; output=%q", c.name, out)
		case !c.wantRedact && !leaked:
			t.Errorf("%s: documented as not prevented, but the redactor caught it. "+
				"That is an improvement: move it to wantRedact and say so in "+
				"docs/redaction.md; output=%q", c.name, out)
		}
	}
}

// TestAdversarialTimeoutFlush proves the partial-output path: a command that
// prints the secret (raw and hex) and then hangs past its timeout is killed,
// but what it printed first must still come back redacted. The executor runs
// redactor.Flush() on every exit path, including the abort, so no buffered raw
// output escapes when the child is cut short.
func TestAdversarialTimeoutFlush(t *testing.T) {
	h := newHarness(t)

	script := `printf 'TOK=%s\n' "$ROUTER_PW"; ` +
		`s="$ROUTER_PW"; for ((i=0;i<${#s};i++)); do printf '%02x' "'${s:$i:1}"; done; printf '\n'; ` +
		`sleep 30`
	r := h.call(t, map[string]any{
		"op":          "exec",
		"cmd":         []any{"bash", "-lc", script},
		"env_refs":    map[string]any{"ROUTER_PW": "secret://home/router/admin"},
		"timeout_sec": 1,
	})
	if r.Error != nil {
		t.Fatalf("broker error: %v", r.Error)
	}
	out := r.Output

	if !strings.Contains(out, token) {
		t.Errorf("expected the printed secret to come back as a token; output=%q", out)
	}
	if !strings.Contains(out, "timed out") {
		t.Errorf("expected a timeout notice; output=%q", out)
	}
	if strings.Contains(out, routerPassword) {
		t.Errorf("RAW SECRET LEAKED on the timeout path: %q", out)
	}
	if hx := recoverableHexLower(routerPassword); strings.Contains(out, hx) {
		t.Errorf("HEX SECRET LEAKED on the timeout path: %q", out)
	}
	fmt.Printf("\ntimeout-flush: printed-then-killed output came back redacted (%d bytes, token present, no raw/hex)\n\n", len(out))
}

func b64(s string) string {
	const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var b strings.Builder
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var n uint32
		var pad int
		n |= uint32(data[i]) << 16
		if i+1 < len(data) {
			n |= uint32(data[i+1]) << 8
		} else {
			pad++
		}
		if i+2 < len(data) {
			n |= uint32(data[i+2])
		} else {
			pad++
		}
		b.WriteByte(std[(n>>18)&63])
		b.WriteByte(std[(n>>12)&63])
		if pad < 2 {
			b.WriteByte(std[(n>>6)&63])
		} else {
			b.WriteByte('=')
		}
		if pad < 1 {
			b.WriteByte(std[n&63])
		} else {
			b.WriteByte('=')
		}
	}
	return b.String()
}

func reverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

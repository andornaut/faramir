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
			wantRedact: false,
		},
		{
			name:       "raw value line-wrapped every 8 cols (fold/fmt/openssl -text)",
			kind:       "ACCIDENTAL",
			script:     `s="$ROUTER_PW"; for ((i=0;i<${#s};i+=8)); do printf '%s\n' "${s:$i:8}"; done`,
			needle:     routerPassword, // present once newlines are removed
			rejoinNL:   true,
			wantRedact: false,
		},
		{
			name:       "rev (documented Not-prevented)",
			kind:       "ADVERSARIAL",
			script:     `printf '%s' "$ROUTER_PW" | rev`,
			needle:     reverseStr(routerPassword),
			wantRedact: false,
		},
	}

	fmt.Printf("\n%-58s %-11s %s\n", "CASE", "KIND", "RESULT")
	fmt.Println(strings.Repeat("-", 90))
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
		fmt.Printf("%-58s %-11s %s\n", c.name, c.kind, result)

		// Assert the control behaves as the design claims; the rest are
		// observations, not failures (the design documents them as out of the
		// exhaustive set).
		if c.wantRedact && leaked {
			t.Errorf("%s: expected redaction but secret form leaked; output=%q", c.name, out)
		}
	}
	fmt.Println()
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

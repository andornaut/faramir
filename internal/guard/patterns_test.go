package guard

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"text/template"

	"github.com/andornaut/faramir/internal/install"
)

const shippedPatterns = "../../agent/hooks/deny-patterns.txt"

// The shipped file is a template, so the paths it refuses are the ones an
// install writes into it.  Rendered against the compiled defaults.
func renderShippedBytes() ([]byte, error) {
	data, err := os.ReadFile(shippedPatterns)
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("deny").Funcs(template.FuncMap{
		"regexQuote": regexp.QuoteMeta,
	}).Parse(string(data))
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	if err := tmpl.Execute(&out, install.Layout{
		ConfigDir:  install.DefaultConfigDir,
		BinDir:     install.DefaultBinDir,
		LibexecDir: install.DefaultLibexecDir,
		LogDir:     install.DefaultLogDir,
	}); err != nil {
		return nil, err
	}
	return []byte(out.String()), nil
}

func renderShipped(t *testing.T) string {
	t.Helper()
	data, err := renderShippedBytes()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func shippedLines(t *testing.T) []string {
	t.Helper()
	data := []byte(renderShipped(t))
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// RE2 has no lookahead or backreferences, and a pattern that fails to compile
// is skipped at load, silently weakening the list.
func TestEveryShippedPatternCompilesUnderRE2(t *testing.T) {
	lines := shippedLines(t)
	if len(lines) == 0 {
		t.Fatal("no patterns in the shipped file")
	}
	for _, pattern := range lines {
		if _, err := regexp.Compile("(?i)" + pattern); err != nil {
			t.Errorf("shipped pattern does not compile under RE2: %q: %v", pattern, err)
		}
	}
}

// A fallback weaker than the shipped list turns an install problem into a
// silent gap.
func TestTheFallbackMatchesTheShippedFile(t *testing.T) {
	shipped := shippedLines(t)
	if len(shipped) != len(fallback) {
		t.Fatalf("shipped file has %d patterns, fallback has %d", len(shipped), len(fallback))
	}
	for i := range shipped {
		if shipped[i] != fallback[i] {
			t.Errorf("pattern %d differs:\n  shipped:  %s\n  fallback: %s", i, shipped[i], fallback[i])
		}
	}
}

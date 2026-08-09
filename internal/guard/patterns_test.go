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

// The shipped file is a template: the paths worth refusing belong to an
// install, not to the source tree, so an operator who moved the config and the
// store into a home gets rules naming where they actually are.  Rendering it
// against the compiled defaults is what the fallback has to match, and is what
// the other tests here match against.
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
		SecretsDir: install.DefaultConfigDir + "/secrets",
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

// Every shipped pattern must compile under RE2.  Python's `re` accepts
// lookahead and backreferences; Go's regexp does not, and a pattern that fails
// to compile is skipped at load, silently weakening the list.  This is the
// exact failure mode the port could introduce, so it is asserted rather than
// assumed.
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

// The shipped file and the built-in fallback have to agree.  A fallback weaker
// than the shipped list turns an install problem into a silent gap.
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

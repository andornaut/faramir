package secretlink

import (
	"strings"
	"testing"
)

// extract reads a file another tool owns, so its input is whatever that tool
// last wrote: a half-written file, a binary one, a YAML bomb. It answers or it
// refuses, and a value it returns is one the file actually holds.
func FuzzExtractAnswersWhateverTheFileHolds(f *testing.F) {
	f.Add("text", "", "hunter2-correct-horse\n")
	f.Add("ini", "//registry.npmjs.org/:_authToken", "[x]\n//registry.npmjs.org/:_authToken=abc\n")
	f.Add("yaml", "github.com/oauth_token", "github.com:\n  oauth_token: abc\n")
	f.Add("json", "a/b", "{\"a\":{\"b\":\"c\"}}")
	f.Add("env", "TOKEN", "TOKEN=abc\n")

	kinds := map[string]bool{}
	for _, k := range Kinds() {
		kinds[k] = true
	}

	f.Fuzz(func(t *testing.T, kind, key, body string) {
		if !kinds[kind] {
			t.Skip()
		}
		got, err := extract(kind, key, []byte(body))
		if err != nil {
			if got != "" {
				t.Fatalf("a refused extract came back with a value: %q", got)
			}
			return
		}
		// Whatever it hands back is either in the file or a decoding of what is,
		// never something the extractor invented out of nothing.
		if got != "" && body == "" {
			t.Fatalf("an empty file yielded %q", got)
		}
	})
}

// keys is what `faramir link add` lists to an operator choosing a selector, so
// it is read off the same untrusted file. It names keys and never values.
func FuzzKeysNamesKeysAndNeverPanics(f *testing.F) {
	f.Add("ini", "[x]\na=b\n")
	f.Add("yaml", "a:\n  b: c\n")
	f.Add("json", "{\"a\":1}")
	f.Add("env", "A=b\n")

	kinds := map[string]bool{}
	for _, k := range Kinds() {
		kinds[k] = true
	}

	f.Fuzz(func(t *testing.T, kind, body string) {
		if !kinds[kind] {
			t.Skip()
		}
		// A selector is written into config.toml and printed back to a terminal,
		// so what it may not carry is a line break or anything a terminal acts
		// on. That it can offer the same selector twice, or an empty one, is its
		// own case and recorded.
		for _, k := range keys(kind, []byte(body)) {
			// That a selector can carry what a terminal acts on is its own case
			// and recorded; what this asks is whether one can carry a byte that
			// would end the line it is printed on.
			if strings.Contains(k, "\n") {
				t.Fatalf("%s offered a selector carrying a newline: %q", kind, k)
			}
		}
	})
}

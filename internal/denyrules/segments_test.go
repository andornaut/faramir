package denyrules

import (
	"slices"
	"testing"
)

// What a command line is made of, which is what decides how far a rule reaches.
func TestSegmentsSplitsAtTheSeparatorsThatEndACommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want []string
	}{
		{"one command", "cat /etc/faramir/age.key", []string{"cat /etc/faramir/age.key"}},
		{"a semicolon", "head a; echo b", []string{"head a", "echo b"}},
		{"a pipe", "head a | grep b", []string{"head a", "grep b"}},
		{"a newline", "head a\necho b", []string{"head a", "echo b"}},
		{"backgrounding", "head a & echo b", []string{"head a", "echo b"}},
		// "&&" and "||" are two characters and split once, the empty piece
		// between them being nothing to match against.
		{"and-and", "head a && echo b", []string{"head a", "echo b"}},
		{"or-or", "head a || echo b", []string{"head a", "echo b"}},
		{"several", "a; b | c\nd", []string{"a", "b", "c", "d"}},

		// Quoting, which is the whole reason this is not a character class.
		{"a semicolon in single quotes", `python3 -c 'import os; open("k")'`,
			[]string{`python3 -c 'import os; open("k")'`}},
		{"a semicolon in double quotes", `python3 -c "x=1; open('k')"`,
			[]string{`python3 -c "x=1; open('k')"`}},
		{"a pipe in quotes", `grep 'a|b' file`, []string{`grep 'a|b' file`}},
		{"an ampersand in quotes", `awk 'BEGIN{x=1&&2}' file`, []string{`awk 'BEGIN{x=1&&2}' file`}},
		// A quoted argument belongs to the command it is in, and the separator
		// after it still ends that command.
		{"quotes then a separator", `head -20 "a.txt"; echo "b"`,
			[]string{`head -20 "a.txt"`, `echo "b"`}},
		{"single quotes then a separator", `head -20 'a.txt'; echo 'b'`,
			[]string{`head -20 'a.txt'`, `echo 'b'`}},
		// The shape that defeated a character class: a quoted script ending in a
		// character that could open a quote.
		{"a sed script then a pipe", `sed 's/a/b/' x | grep 'k'`,
			[]string{`sed 's/a/b/' x`, `grep 'k'`}},

		// Escapes.
		{"a line continuation", "cat \\\n  /etc/faramir/age.key",
			[]string{"cat \\\n  /etc/faramir/age.key"}},
		{"an escaped semicolon", `find . -exec rm {} \; -print`,
			[]string{`find . -exec rm {} \; -print`}},
		{"an escaped quote in double quotes", `echo "a\"b; c"`, []string{`echo "a\"b; c"`}},

		// Redirection, where "&" is not the end of anything.
		{"stderr to stdout", "cat 2>&1 /etc/faramir/age.key",
			[]string{"cat 2>&1 /etc/faramir/age.key"}},
		{"both streams", "cat &> /tmp/x /etc/faramir/age.key",
			[]string{"cat &> /tmp/x /etc/faramir/age.key"}},
		{"stdout to stderr", "cat 1>&2 k", []string{"cat 1>&2 k"}},

		// A quote that never closes: one segment, which refuses more rather
		// than less.
		{"an unterminated double quote", `cat "a; echo b`, []string{`cat "a; echo b`}},
		{"an unterminated single quote", `cat 'a; echo b`, []string{`cat 'a; echo b`}},
		// A line that cannot be read is returned whole, earlier splits included:
		// a longer segment matches everything a shorter one would and more, so
		// the guess that costs a needless refusal is the one to make.
		{"a split before an unterminated quote", `head a; cat "b; c`,
			[]string{`head a; cat "b; c`}},

		{"empty", "", nil},
		{"separators only", ";;|&", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Segments(tc.line); !slices.Equal(got, tc.want) {
				t.Errorf("Segments(%q) =\n  %q\nwant\n  %q", tc.line, got, tc.want)
			}
		})
	}
}

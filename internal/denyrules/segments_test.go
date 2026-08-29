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

// A heredoc body is read as commands, whichever way its delimiter is spelled.
//
// The quoted spelling was skipped for a while, on the reasoning that `<<'EOF'`
// makes its body literal data. It does, and literal data is what an interpreter
// runs: `bash <<'EOF'` executes every line of it, and nothing in the redirection
// separates that from `cat <<'EOF' > doc`. Skipping the body took a read of key
// material inside an interpreter heredoc out of the deny list entirely.
//
// What it costs is the case the exemption was added for: writing a document that
// quotes an operator command is refused. That is a refusal and not a disclosure,
// and the two are not traded at the same rate.
func TestSegmentsReadsAHeredocBodyAsCommands(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want []string
	}{
		// THE REGRESSION: an interpreter runs the body, quoted delimiter and all.
		{"a body fed to bash", "bash <<'EOF'\ncat /etc/faramir/age.key\nEOF",
			[]string{"bash <<'EOF'", "cat /etc/faramir/age.key", "EOF"}},
		{"a body fed to sh", "sh <<'EOF'\ncat /etc/faramir/age.key\nEOF",
			[]string{"sh <<'EOF'", "cat /etc/faramir/age.key", "EOF"}},
		{"a body piped into bash", "cat <<'EOF' | bash\ncat /etc/faramir/age.key\nEOF",
			[]string{"cat <<'EOF'", "bash", "cat /etc/faramir/age.key", "EOF"}},

		// And the cost, written down rather than left to be met: a document that
		// quotes an operator command is refused the same way.
		{"a single-quoted delimiter written to a file", "cat > doc <<'EOF'\nsudo faramir doctor\nEOF",
			[]string{"cat > doc <<'EOF'", "sudo faramir doctor", "EOF"}},
		{"a double-quoted delimiter", "cat > doc <<\"EOF\"\nsudo faramir doctor\nEOF",
			[]string{"cat > doc <<\"EOF\"", "sudo faramir doctor", "EOF"}},
		{"an unquoted delimiter", "cat > doc <<EOF\nsudo faramir doctor\nEOF",
			[]string{"cat > doc <<EOF", "sudo faramir doctor", "EOF"}},

		// A herestring is not a heredoc: its word is data on the line it is on and
		// no body follows, so the lines after it are ordinary commands.
		{"a herestring", "grep x <<< 'sudo faramir doctor'",
			[]string{"grep x <<< 'sudo faramir doctor'"}},
		{"commands after a herestring are still read", "grep x <<< 'A'\nsudo faramir doctor\nA\necho done",
			[]string{"grep x <<< 'A'", "sudo faramir doctor", "A", "echo done"}},
		{"and with no space before the word", "grep x <<<'A'\nsudo faramir doctor\nA\necho done",
			[]string{"grep x <<<'A'", "sudo faramir doctor", "A", "echo done"}},

		{"a heredoc inside quotes is still just text", "echo \"a <<'EOF' b\"; sudo faramir doctor",
			[]string{"echo \"a <<'EOF' b\"", "sudo faramir doctor"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Segments(tc.line); !slices.Equal(got, tc.want) {
				t.Errorf("Segments(%q) =\n  %q\nwant\n  %q", tc.line, got, tc.want)
			}
		})
	}
}

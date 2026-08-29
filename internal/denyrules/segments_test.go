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

// A quoted heredoc body is a file being written, not commands being run. This
// is what lets a script or a document quote an operator command without the
// quotation being refused as the command itself.
func TestSegmentsReadsAQuotedHeredocBodyAsData(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want []string
	}{
		{"a single-quoted delimiter", "cat > doc <<'EOF'\nsudo faramir vault add x\nEOF",
			[]string{"cat > doc <<'EOF'"}},
		{"a double-quoted delimiter", "cat > doc <<\"EOF\"\nsudo faramir doctor\nEOF",
			[]string{"cat > doc <<\"EOF\""}},
		{"a command after the terminator still counts", "cat > doc <<'EOF'\nsudo faramir doctor\nEOF\necho done",
			[]string{"cat > doc <<'EOF'", "echo done"}},
		{"the opening line still splits", "true | cat > doc <<'EOF'\ncat /etc/faramir/age.key\nEOF",
			[]string{"true", "cat > doc <<'EOF'"}},
		// `<<-` strips leading tabs from the terminator and nothing else.
		{"a tab-indented terminator", "cat <<-'EOF'\nsudo faramir doctor\n\tEOF\necho done",
			[]string{"cat <<-'EOF'", "echo done"}},
		//nolint:dupword // the repeated EOF is the fixture: a space-indented terminator does not end a <<- heredoc, so the next one has to
		{"spaces do not terminate a tab heredoc", "cat <<-'EOF'\nx\n  EOF\nEOF\necho done",
			[]string{"cat <<-'EOF'", "echo done"}},
		{"two heredocs on one line", "join <<'A' <<'B'\ncat /etc/faramir/age.key\nA\nsudo faramir doctor\nB\necho done",
			[]string{"join <<'A' <<'B'", "echo done"}},

		// THE REFUSAL: an unquoted delimiter expands `$(...)` and backticks in
		// its body, so the body is commands and is read as commands.
		{"an unquoted delimiter", "cat > doc <<EOF\nsudo faramir doctor\nEOF",
			[]string{"cat > doc <<EOF", "sudo faramir doctor", "EOF"}},
		{"a herestring is not a heredoc", "grep x <<< 'sudo faramir doctor'",
			[]string{"grep x <<< 'sudo faramir doctor'"}},
		// And the lines after one are still commands. A herestring's word is
		// quoted exactly as a delimiter is, so a reader that starts at the second
		// "<" takes it for one and skips every line up to the next line matching
		// it: the commands between are then never matched against the deny list,
		// whatever they are. Both spellings, the space being optional.
		{"commands after a herestring are still read", "grep x <<< 'A'\nsudo faramir doctor\nA\necho done",
			[]string{"grep x <<< 'A'", "sudo faramir doctor", "A", "echo done"}},
		{"and with no space before the word", "grep x <<<'A'\nsudo faramir doctor\nA\necho done",
			[]string{"grep x <<<'A'", "sudo faramir doctor", "A", "echo done"}},
		// A terminator that never arrives leaves the line unreadable, so none of
		// it is split: the shape that refuses more rather than less.
		{"no terminator", "cat > doc <<'EOF'\nsudo faramir doctor\n",
			[]string{"cat > doc <<'EOF'\nsudo faramir doctor"}},
		{"a heredoc opened and the line ends", "cat > doc <<'EOF'",
			[]string{"cat > doc <<'EOF'"}},
		{"an unterminated delimiter quote", "cat > doc <<'EOF\nsudo faramir doctor\nEOF",
			[]string{"cat > doc <<'EOF\nsudo faramir doctor\nEOF"}},
		{"a heredoc inside quotes is not one", "echo \"a <<'EOF' b\"; sudo faramir doctor",
			[]string{"echo \"a <<'EOF' b\"", "sudo faramir doctor"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Segments(tc.line); !slices.Equal(got, tc.want) {
				t.Errorf("Segments(%q) =\n  %q\nwant\n  %q", tc.line, got, tc.want)
			}
		})
	}
}

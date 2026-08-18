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
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// A fallback weaker than the shipped list turns an install problem into a
// silent gap.
//
// Byte equality is also what makes one compile check enough for both.  RE2 has
// no lookahead or backreferences, and a pattern that fails to compile is
// skipped at load rather than reported, but TestEveryFallbackPatternCompiles
// asserts that none of the fallback is skipped, and equality carries that to
// the shipped file.
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

// Every refusal explains itself with the reason it was actually refused for.
//
// The deny list holds two kinds of rule and they need different messages. A
// read rule is about what the command would disclose, and faramir_run is the
// way to proceed. A rule about faramir's own files, accounts or units discloses
// nothing, and faramir_run is not a remedy there: it runs as an account with
// less reach, so following that advice either hits a permission error or, where
// the executor does have reach, does the thing that was refused.
func TestARefusalExplainsWhyItWasRefused(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    string
	}{
		// Disclosure: what the command would put in the conversation.
		{"cat ~/.ssh/id_ed25519", advice},
		{"sops -d secrets.sops.yml", advice},
		{"printenv", advice},
		{"cat /home/op/.config/sops/age/keys.txt", advice},
		{"age-keygen", advice},
		{"sudo -u faramir-keeper cat /etc/faramir/age.key", advice},
		// faramir's own. Nothing here is disclosed; something is changed or stopped.
		{"rm /etc/faramir/age.key", adviceOwn},
		{"echo x > /etc/faramir/config.toml", adviceOwn},
		{"systemctl stop faramir-broker.socket", adviceOwn},
		{"rm .opencode/plugins/faramir.js", adviceOwn},
		{"sed -i s/x/y/ .pi/extensions/faramir.ts", adviceOwn},
		// The operator's. Every faramir subcommand under sudo, the daemons and the
		// escalation channel among them: an agent has no root to run one with, and
		// a refusal saying so is more use than one about disclosure.
		{"sudo faramir keeper", adviceOperator},
		{"sudo faramir approve abc123", adviceOperator},
		{"sudo faramir escalations", adviceOperator},
		{"sudo faramir deny abc123", adviceOperator},
		{"sudo faramir access --read /etc/faramir/age.key", adviceOperator},
		{"sudo faramir doctor", adviceOperator},
		// And the same set unprivileged, which is where an agent meets it.
		{"faramir doctor", adviceOperator},
		{"faramir logs", adviceOperator},
		{"faramir vault edit app", adviceOperator},
		{"faramir uninstall", adviceOperator},
	} {
		t.Run(tc.command, func(t *testing.T) {
			pattern, denied := decide(tc.command)
			if !denied {
				t.Fatalf("%q was not refused, so this says nothing about its message", tc.command)
			}
			if got := adviceFor(pattern); got != tc.want {
				t.Errorf("%q was explained with the wrong message (pattern %s): a refusal "+
					"naming the wrong remedy sends the agent somewhere that cannot help",
					tc.command, pattern)
			}
		})
	}
}

// A pattern added to the list gets classified by this test rather than by
// whichever branch it happens to fall into. The counts are the forcing function:
// changing the list fails here until somebody says which message the new rule
// carries.
func TestEveryPatternIsClassifiedOnPurpose(t *testing.T) {
	counts := map[string]int{}
	for _, pattern := range fallback {
		counts[adviceFor(pattern)]++
	}
	for _, tc := range []struct {
		name  string
		which string
		want  int
	}{
		{"faramir's own", adviceOwn, 5},
		{"the operator's", adviceOperator, 2},
	} {
		if counts[tc.which] != tc.want {
			t.Errorf("%d of %d patterns explain themselves as %s, want %d. A rule was "+
				"added or moved: decide which message it should carry, add it to "+
				"TestARefusalExplainsWhyItWasRefused, and update this count",
				counts[tc.which], len(fallback), tc.name, tc.want)
		}
	}
}

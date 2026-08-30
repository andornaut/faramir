package guard

import (
	"regexp"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/install"
)

// The shipped file is a template, so the paths it refuses are the ones an
// install writes into it. Rendered against the compiled defaults.
func renderShippedBytes() ([]byte, error) {
	// install's own rendering rather than a second one here: the file now carries
	// generated rules, and a test that built it another way would assert on rules
	// nobody installs.
	return install.RenderDenyPatterns(install.Layout{
		ConfigDir:  install.DefaultConfigDir,
		BinDir:     install.DefaultBinDir,
		LibexecDir: install.DefaultLibexecDir,
		LogDir:     install.DefaultLogDir,
		BrokerUser: install.DefaultBrokerUser,
		KeeperUser: install.DefaultKeeperUser,
		ExecUser:   install.DefaultExecUser,
	})
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
// Byte equality is also what makes one compile check enough for both. RE2 has
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
// read rule is about what the command would disclose, and faramir run is the
// way to proceed. A rule about faramir's own files, accounts or units discloses
// nothing, and faramir run is not a remedy there: it runs as an account with
// less reach, so following that advice either hits a permission error or, where
// the executor does have reach, does the thing that was refused.
func TestARefusalExplainsWhyItWasRefused(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    string
	}{
		// One of this install's own directories, however it was reached. There
		// is no entry over these to take back, so the message says so rather
		// than naming a removal command that would not find one.
		{"sops -d /etc/faramir/secrets/db.sops.yml", adviceOwnPath},
		{"cat /etc/faramir/secrets/db.sops.yml", adviceOwnPath},
		{"rm /etc/faramir/age.key", adviceOwnPath},
		{"echo x > /etc/faramir/age.key", adviceOwnPath},
		// Under sudo it is the operator's, which is the more useful answer and
		// is why those rules are matched first.
		{"sudo -u faramir-keeper cat /etc/faramir/age.key", adviceOperator},
		{"sudo env -u faramir-exec sh -c 'cat /srv/luks.key'", adviceOperator},
		{"systemctl stop faramir-broker.socket", adviceOwn},
		{"rm ~/.config/opencode/plugin/faramir.js", adviceOwn},
		{"sed -i s/x/y/ ~/.pi/agent/extensions/faramir.ts", adviceOwn},
		// The operator's. Every faramir subcommand under sudo, the daemons and the
		// escalation channel among them: an agent has no root to run one with, and
		// a refusal saying so is more use than one about disclosure.
		{"sudo faramir keeper", adviceOperator},
		{"sudo faramir sudo approve abc123", adviceOperator},
		{"sudo faramir sudo ls", adviceOperator},
		{"sudo faramir sudo watch", adviceOperator},
		{"sudo faramir sudo reject abc123", adviceOperator},
		{"sudo faramir reader add age1abc", adviceOperator},
		{"sudo faramir reader reseal", adviceOperator},
		{"sudo faramir access --read /etc/faramir/age.key", adviceOperator},
		{"sudo faramir doctor", adviceOperator},
		// And the same set unprivileged, which is where an agent meets it.
		// `logs` is here rather than among the listings: it needs root, so a
		// refusal naming the operator is the true answer and a permission error
		// would not be.
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
//
// Counted against a command naming this install's own directory, which is what
// the fallback's one subject rule is about: the fallback holds no declared path,
// having no config to read one from. The kinds an install does render are
// TestADeclaredPathIsAnsweredByItsKind.
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
		// Five: the binary's two, the plugin files' two, and systemctl.
		{"faramir's own", adviceOwn, 5},
		// Three: a faramir subcommand under sudo, the same set unprivileged, and
		// running as one of the service accounts.
		{"the operator's", adviceOperator, 3},
		// The subject rule, which says which kind it is. The fallback's is the
		// install's own directories and nothing else: it holds no declared path,
		// having no config to read one from.
		{"one of faramir's own directories", adviceOwnPath, 1},
		// Nothing falls through. adviceDeclared is the default for a rule no
		// marker classified, and every rule here is classified.
		{"a declared path", adviceDeclared, 0},
	} {
		if counts[tc.which] != tc.want {
			t.Errorf("%d of %d patterns explain themselves as %s, want %d. A rule was "+
				"added or moved: decide which message it should carry, add it to "+
				"TestARefusalExplainsWhyItWasRefused, and update this count",
				counts[tc.which], len(fallback), tc.name, tc.want)
		}
	}
}

// The listings describe the install without changing it and without printing a
// value, so they are not refused. Each was already reachable as `faramir run --
// faramir <command>`, which takes no root and raises no approval: refusing the
// direct spelling left the two routes disagreeing and bought nothing.
//
// Asserted per command rather than through cli.ReadOnly, so moving one out of
// that list fails here rather than quietly widening what an agent may run.
func TestTheReadOnlyListingsAreNotRefused(t *testing.T) {
	for _, command := range []string{
		"faramir block ls",
		"faramir link ls",
		"faramir reader ls",
		"faramir doctor",
		"faramir block ls --declared",
	} {
		if pattern, denied := decide(command); denied {
			t.Errorf("%q is refused by %q, and it only describes the install",
				command, pattern)
		}
	}
}

// Under sudo they stay refused, and so does every write verb: what changed is
// which commands an agent may run as itself, not what it may run as root.
func TestTheReadOnlyListingsAreStillRefusedUnderSudo(t *testing.T) {
	for _, command := range []string{
		"sudo faramir block ls",
		"sudo faramir doctor",
		"sudo faramir reader ls",
	} {
		if _, denied := decide(command); !denied {
			t.Errorf("%q is allowed, and an agent has no root to run it with", command)
		}
	}
}

// The write verbs of the same groups are untouched by the read-only exemption:
// "block ls" being runnable must not make "block rm" so.
func TestTheWriteVerbsAreStillRefused(t *testing.T) {
	for _, command := range []string{
		"faramir block add --path /etc/x",
		"faramir block rm --path /etc/x",
		"faramir link add --ref a --path /etc/x",
		"faramir link rm --ref a",
		"faramir reader add age1abc",
		"faramir reader rm age1abc",
		"faramir vault ls",
		"faramir sudo ls",
		"faramir logs",
	} {
		if _, denied := decide(command); !denied {
			t.Errorf("%q is allowed, and it is the operator's", command)
		}
	}
}

// A declared path is answered by the kind of entry that declared it, which is
// the only thing that says how the agent stops being refused. The rules are the
// same shape, so nothing but the kind written into them tells the three apart,
// and an agent told to run the wrong removal command is sent somewhere that
// cannot help.
func TestADeclaredPathIsAnsweredByItsKind(t *testing.T) {
	for _, tc := range []struct {
		kind denyrules.Kind
		want string
	}{
		{denyrules.KindBlocked, adviceBlockedPath},
		{denyrules.KindLinked, adviceLinkedPath},
		{denyrules.KindOwn, adviceOwnPath},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			rules := denyrules.NamingAs(tc.kind, []string{denyrules.Dir("/srv/luks.key")})
			if len(rules) != 1 {
				t.Fatalf("%d rules for one subject, want 1", len(rules))
			}
			for _, command := range []string{
				"rm /srv/luks.key",
				"cat /srv/luks.key",
				"echo x > /srv/luks.key",
			} {
				// The kind changes the message and not what is refused: the
				// rule has to still match, or the message it carries is moot.
				if !regexp.MustCompile(rules[0]).MatchString(command) {
					t.Errorf("%q is not refused by the %s rule", command, tc.kind)
					continue
				}
				if got := adviceFor(rules[0]); got != tc.want {
					t.Errorf("%q was explained with the wrong message for a %s path: "+
						"the three rules look alike and only the kind tells them apart",
						command, tc.kind)
				}
			}
		})
	}
}

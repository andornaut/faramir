package denyrules

import (
	"regexp"
	"strings"

	"github.com/andornaut/faramir/internal/cli"
)

// The rules about faramir's own commands and files, which are the part of the
// catalogue that is not a function of the config. Patterns rather than
// subjects: they say what a command does rather than what it points at, so
// there is no looser reading to give one and both tiers take them as written.
//
// Here rather than beside either tier. A list one tier holds and hands to the
// other is a list that can be handed to neither, and that is how a brokered
// operator subcommand came to meet no rule while the bare spelling was refused
// to a shell.

// pluginFiles is the one alternation both plugin-file rules carry: the plugin,
// extension and hook file `faramir init` installs, which are faramir's own files
// and the only thing refusing those agents' file tools.
const pluginFiles = `(opencode/plugin/faramir\.js|kilo/plugin/faramir\.js|pi/agent/extensions/faramir\.ts|codex/hooks\.json)`

// ActionRules is the three groups, each under the kind that decides what a
// refusal says about it. Both tiers read them from here, so neither can hold a
// group the other does not.
func ActionRules() []Rule {
	return []Rule{
		{Kind: KindOwnAction, Patterns: fallbackOwnFiles},
		{Kind: KindOperator, Patterns: fallbackOperator},
		{Kind: KindOwnAction, Patterns: fallbackOwnUnits},
	}
}

// fallbackOwnFiles is faramir's own binary and the files an enrolment installs.
var fallbackOwnFiles = []string{
	// The binary, named as one path rather than as its directory, or installing
	// any unrelated tool into /usr/local/bin would be refused.
	WriteCommands + ArgSpan + `/usr/local/bin/faramir\b`,
	`>\s*\S*/usr/local/bin/faramir\b`,
	// The plugin, extension and hook file `faramir init` installs, which are
	// faramir's own files and now the only thing refusing those agents' file
	// tools: deleting one is deleting their cover. The directories are
	// ~/.config/opencode, ~/.config/kilo, ~/.pi/agent and ~/.codex, and Codex's is
	// also a tree's own file, so one spelling covers ~/.codex/hooks.json and a
	// project's .codex/hooks.json.
	//
	// Matched as a suffix with no leading dot, which is wider than those
	// directories: "somecodex/hooks.json" matches too. Over-refusal, on files
	// nothing else writes, and narrowing it would cost the one spelling that
	// reaches both a home and a tree.
	//
	// The merged files (.claude/settings.json, opencode.json, kilo.json) are
	// deliberately absent: they carry the operator's own settings beside
	// faramir's, so editing them is ordinary work, and `faramir doctor` reports a
	// registration that went missing.
	WriteCommands + ArgSpan + pluginFiles,
	`>\s*\S*` + pluginFiles,
}

// fallbackOperator is the commands that act on the install rather than through
// it, which are the operator's by either route.
var fallbackOperator = []string{
	// faramir under sudo, whichever subcommand. Nothing an agent may run needs
	// root -- `run`, `redact`, `status` and `refs` all answer as the agent's own
	// account -- so a sudo here is a daemon, a decision that is the operator's, or
	// a change to the install. Only sudo's own flags may precede the name.
	// Managing a unit is not this, so "systemctl restart faramir-keeper" stays
	// allowed, as does journalctl.
	`\bsudo\b(\s+-\S+)*\s+faramir\b`,
	// The same commands unprivileged. They act on the install rather than through
	// it, so they are the operator's whether or not sudo is in front: refused here
	// so the agent is told that rather than meeting a permission error it will try
	// to work around. Derived from cli.OperatorOnly, so a command added there is
	// refused here without a second list to update; the shipped file's copy is
	// held to this one by TestTheFallbackMatchesTheShippedFile.
	`\bfaramir[-\s]+(` + SubcommandAlternation(cli.OperatorOnly()) + `)\b`,
	`\bsudo\b.*-u\s+faramir`,
}

// fallbackOwnUnits is managing one of faramir's units. Blocked for what it
// costs, not because it hides anything: the wrapper fails closed, so a stopped
// broker withholds every command's output in every enrolled tree at once.
var fallbackOwnUnits = []string{
	`\bsystemctl\b.*\b(stop|disable|mask|kill|edit)\b.*\bfaramir-`,
}

// SubcommandAlternation renders subcommand names as one alternation. A grouped
// command is named as two tokens, so the space between them becomes the
// whitespace a shell would accept: `vault edit` has to match `vault   edit` and
// must not match `vaultedit`.
func SubcommandAlternation(names []string) string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, strings.ReplaceAll(regexp.QuoteMeta(name), " ", `[ \t]+`))
	}
	return strings.Join(out, "|")
}

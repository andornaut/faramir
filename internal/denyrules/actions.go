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

// Action is one rule about what a command does, and the phrase that says so.
// A pattern is a regular expression, which is the one thing `faramir block ls`
// prints that an operator cannot read, so what a rule refuses is written beside
// it here rather than worked out by whoever renders the listing.
type Action struct {
	Pattern string
	// Refuses is the phrase a listing prints on its own line, so it is a noun
	// phrase naming what the rule matches rather than a sentence: nothing
	// prepends a verb to it.
	//
	// It says what the pattern does and not what the rule is for. A description
	// wider than its pattern reports a refusal that will not happen, which is
	// worse than the regular expression it replaced: an operator can read a
	// pattern and be right, and can only take this on trust.
	Refuses string
}

// ActionRules is the three groups, each under the kind that decides what a
// refusal says about it. Both tiers read them from here, so neither can hold a
// group the other does not.
func ActionRules() []Rule {
	return []Rule{
		{Kind: KindOwnAction, Patterns: patternsOf(fallbackOwnFiles)},
		{Kind: KindOperator, Patterns: patternsOf(fallbackOperator)},
		{Kind: KindOwnAction, Patterns: patternsOf(fallbackOwnUnits)},
	}
}

// actionGroups is the three groups as they are written, which is what carries
// the descriptions. ActionRules drops them, holding the patterns alone.
func actionGroups() [][]Action {
	return [][]Action{fallbackOwnFiles, fallbackOperator, fallbackOwnUnits}
}

// patternsOf is a group's patterns in the order it holds them, which is the
// order both tiers compile.
func patternsOf(actions []Action) []string {
	out := make([]string, 0, len(actions))
	for _, action := range actions {
		out = append(out, action.Pattern)
	}
	return out
}

// DescribeAction is what one action pattern refuses, in the words a listing
// prints in place of it.
//
// Looked up by the pattern rather than by position, because position does not
// survive rendering: GuardRules flattens the groups into Kinds() order, so the
// third rule written here is not the third rule a tier holds. Empty for
// anything that is not one of faramir's own patterns, which is every rule
// generated from the config.
func DescribeAction(pattern string) string {
	for _, group := range actionGroups() {
		for _, action := range group {
			if action.Pattern == pattern {
				return action.Refuses
			}
		}
	}
	return ""
}

// fallbackOwnFiles is faramir's own binary and the files an enrolment installs.
var fallbackOwnFiles = []Action{
	// The binary, named as one path rather than as its directory, or installing
	// any unrelated tool into /usr/local/bin would be refused.
	{
		Pattern: WriteCommands + ArgSpan + `/usr/local/bin/faramir\b`,
		Refuses: "a file-changing command naming faramir's own binary",
	},
	{
		Pattern: `>\s*\S*/usr/local/bin/faramir\b`,
		Refuses: "a redirect into faramir's own binary",
	},
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
	{
		Pattern: WriteCommands + ArgSpan + pluginFiles,
		Refuses: "a file-changing command naming the plugin, extension or hook file an enrolment installs",
	},
	{
		Pattern: `>\s*\S*` + pluginFiles,
		Refuses: "a redirect into the plugin, extension or hook file an enrolment installs",
	},
}

// fallbackOperator is the commands that act on the install rather than through
// it, which are the operator's by either route.
var fallbackOperator = []Action{
	// faramir under sudo, whichever subcommand. Nothing an agent may run needs
	// root -- `run`, `redact`, `status` and `refs` all answer as the agent's own
	// account -- so a sudo here is a daemon, a decision that is the operator's, or
	// a change to the install. Only sudo's own flags may precede the name.
	// Managing a unit is not this, so "systemctl restart faramir-keeper" stays
	// allowed, as does journalctl.
	{
		Pattern: `\bsudo\b(\s+-\S+)*\s+faramir\b`,
		Refuses: "faramir under sudo, whichever subcommand",
	},
	// The same commands unprivileged. They act on the install rather than through
	// it, so they are the operator's whether or not sudo is in front: refused here
	// so the agent is told that rather than meeting a permission error it will try
	// to work around. Derived from cli.OperatorOnly, so a command added there is
	// refused here without a second list to update; the shipped file's copy is
	// held to this one by TestTheFallbackMatchesTheShippedFile.
	{
		Pattern: `\bfaramir[-\s]+(` + SubcommandAlternation(cli.OperatorOnly()) + `)\b`,
		Refuses: "an operator-only subcommand, such as enrol, vault edit or block add",
	},
	{
		Pattern: `\bsudo\b.*-u\s+faramir`,
		Refuses: "a sudo -u naming faramir or one of its service accounts",
	},
}

// fallbackOwnUnits is managing one of faramir's units. Blocked for what it
// costs, not because it hides anything: the wrapper fails closed, so a stopped
// broker withholds every command's output in every enrolled tree at once.
var fallbackOwnUnits = []Action{
	{
		Pattern: `\bsystemctl\b.*\b(stop|disable|mask|kill|edit)\b.*\bfaramir-`,
		Refuses: "stopping, disabling, masking, killing or editing one of faramir's units",
	},
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

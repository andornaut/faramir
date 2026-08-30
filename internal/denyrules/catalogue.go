package denyrules

import (
	"regexp"
	"sort"

	"github.com/andornaut/faramir/internal/config"
)

// A Rule is one thing this host refuses, with what a refusal has to say about
// it. It is the shape both tiers are built from: the guard packs a set of rules
// into a file of patterns and keeps nothing but the kind, that being all such a
// file can carry, while the broker holds one rule per entry and has the entry
// in front of it when it answers.
//
// The two tiers do not read a rule the same way and are not meant to.
// GuardRules and Broker below are that difference, written once and beside each
// other, so a kind added here cannot reach one tier and be forgotten in the
// other. Before this there were two inventories built in two packages, and the
// operator commands were in one of them: a brokered `faramir vault ls` met no
// rule at all.
type Rule struct {
	// Kind decides which of Subjects and Patterns is populated, and which
	// message a refusal carries in either tier.
	Kind Kind
	// Entry is the path or the command the operator declared, as written. Empty
	// for a rule no entry stands behind.
	Entry string
	// Ref is the name a linked file answers to, and empty for every other kind.
	// A refusal names it because asking by ref is what the caller is meant to do
	// instead.
	Ref string
	// Remedy is the command that takes the entry back out, empty where there is
	// none: the directories this install occupies are rendered from its layout
	// on every run, and faramir's own commands are not entries.
	Remedy string
	// Strict is the entry the operator asked to have refused wherever it is
	// named rather than only where a command would print it. It reaches the
	// brokered tier alone, the guard refusing a named path either way.
	Strict bool
	// Subjects are path fragments, which each tier wraps in its own rule shape.
	Subjects []string
	// Patterns are whole rules, for a kind whose subject is a command rather
	// than a path. There is no looser reading to give one, so both tiers take
	// them as written.
	Patterns []string
}

// Kind is what a rule is about, and the one vocabulary both tiers key their
// message off. The strings are written into the rendered file by NamingAs and
// read back out of it by the guard, so they are as fixed as any pattern here.
type Kind string

const (
	// KindOwn is a directory this install occupies, which no entry declares and
	// no removal takes back.
	KindOwn Kind = "own"
	// KindBlocked is a path a [[secret.block]] entry names.
	KindBlocked Kind = "blocked"
	// KindLinked is the file a [[secret.link]] entry reads.
	KindLinked Kind = "linked"
	// KindCommand is a [[secret.block]] entry naming a command rather than a
	// path. What a reader may still do to a file says nothing about one.
	KindCommand Kind = "command"
	// KindOperator is a command that acts on the install rather than through it.
	// The operator's to run by either route: the account the agent runs as could
	// not carry it out, and neither could the executor.
	KindOperator Kind = "operator"
	// KindOwnAction is faramir's own binary, the files an enrolment installs,
	// and its units. Refused for what a command would do to them rather than for
	// anything they would disclose.
	KindOwnAction Kind = "ownaction"
)

// Kinds is every kind, and the order both tiers hold their rules in. A tier
// keying its messages off these has a compile-time list to check itself against
// rather than a habit of remembering, and one that renders them has the order
// as well.
//
// First match wins on both sides, so the order decides which of two rules a
// command that matches both is answered by. What acts on the install comes
// first: an agent running a faramir subcommand against one of its own
// directories is told it is an operator command, which is the more useful of
// the two answers. Own before blocked and linked for the same reason, a path
// that is both this install's own and declared being the install's, which is
// the answer with no removal to offer.
func Kinds() []Kind {
	return []Kind{KindOwnAction, KindOperator, KindOwn, KindBlocked, KindLinked, KindCommand}
}

// List is the table an entry sits in, named the way `faramir block ls` and
// `faramir link ls` are, and empty for a kind no entry stands behind. What a
// refusal must not say is "declared": it names no command its reader could run,
// and does not say which of the two removals applies.
func (k Kind) List() string {
	switch k {
	case KindBlocked, KindCommand:
		return "the blocks"
	case KindLinked:
		return "the links"
	case KindOwn, KindOperator, KindOwnAction:
		// Nothing an entry wrote, so nothing a listing holds and nothing a
		// removal takes back.
		return ""
	}
	return ""
}

// For is everything one host refuses about paths and declared commands, and the
// single inventory both tiers are built from. What it cannot know it is handed:
// home is the home a "~" stands for, and ownDirs is where this install put
// itself, which is the installer's to know.
//
// The config is all it reads. The rules about faramir's own commands and files
// are the same on every host and are not a function of it, so they are
// ActionRules in actions.go, and each tier reads them from there rather than
// being handed them: see the note at the head of that file.
func For(home string, ownDirs []string, secret config.SecretConfig) []Rule {
	out := make([]Rule, 0, len(ownDirs)+len(secret.Blocked)+len(secret.Links))
	for _, dir := range ownDirs {
		out = append(out, Rule{
			Kind:     KindOwn,
			Entry:    dir,
			Strict:   true,
			Subjects: []string{DirUnder(home, dir)},
		})
	}
	linked, blocked := declaredPaths(secret)
	for _, entry := range blocked {
		out = append(out, Rule{
			Kind:     KindBlocked,
			Entry:    entry.Path,
			Remedy:   "`faramir block rm`",
			Strict:   entry.Strict,
			Subjects: subjectsUnder(home, entry.Path),
		})
	}
	for _, link := range linked {
		out = append(out, Rule{
			Kind:     KindLinked,
			Entry:    link.Path,
			Ref:      link.Ref,
			Remedy:   "`faramir link rm`",
			Strict:   link.Strict,
			Subjects: subjectsUnder(home, link.Path),
		})
	}
	// A command is not a path, so no rule above can carry one and no file-tool
	// rule can either. The loader refuses strict on one, a command entry already
	// being about what a command does.
	for _, entry := range secret.Blocked {
		if entry.Command == "" {
			continue
		}
		if rule := CommandRule(entry.Command); rule != "" {
			out = append(out, Rule{
				Kind:     KindCommand,
				Entry:    entry.Command,
				Remedy:   "`faramir block rm --command`",
				Patterns: []string{rule},
			})
		}
	}
	return out
}

// declaredPaths is the path entries this host holds, split by the entry that
// named each one and sorted, so the rendered file does not move when a config
// is rewritten in another order.
//
// A path may be both linked and blocked, and it belongs to the link: the rule
// is the same either way, only the message differs, and taking back a block
// over a path a link already covers refuses nothing less. Deciding it here is
// what keeps the two tiers from deciding it differently, which is how a refusal
// came to offer `faramir block rm` for a file a link was reading.
//
// Strict is the one thing the dropped entry still has to carry. The two entries
// are two readings of one path and the stricter is what the pair asked for, so a
// block written --strict keeps its reading when the link beside it was not:
// dropping the entry may not drop what the flag bought.
func declaredPaths(secret config.SecretConfig) (linked []config.Link, blocked []config.BlockedPath) {
	at := make(map[string]int, len(secret.Links))
	for _, link := range secret.Links {
		if link.Path == "" {
			continue
		}
		if _, held := at[link.Path]; held {
			continue
		}
		at[link.Path] = len(linked)
		linked = append(linked, link)
	}
	seen := make(map[string]bool, len(secret.Blocked))
	for _, entry := range secret.Blocked {
		if entry.Path == "" || seen[entry.Path] {
			continue
		}
		if i, held := at[entry.Path]; held {
			linked[i].Strict = linked[i].Strict || entry.Strict
			continue
		}
		seen[entry.Path] = true
		blocked = append(blocked, entry)
	}
	sort.Slice(linked, func(i, j int) bool { return linked[i].Path < linked[j].Path })
	sort.Slice(blocked, func(i, j int) bool { return blocked[i].Path < blocked[j].Path })
	return linked, blocked
}

// subjectsUnder is the fragments that cover one path: the path and everything
// below it, and a glob in the directory that holds it. A rule for a file
// carries the file's name and a glob does not, so the second is what keeps
// `cat <dir>/*` from reaching it. There is no glob for a path whose parent is a
// home or the root, a pattern rule there answering for every account on the
// host.
func subjectsUnder(home, path string) []string {
	out := []string{DirUnder(home, path)}
	if glob := GlobUnder(home, path); glob != "" {
		out = append(out, glob)
	}
	return out
}

// Compile is how a rule is read, which travels with the rule rather than being
// remembered at each place one is compiled.
//
// Case-insensitively. A path is a path whatever case it is written in on the
// filesystems this runs on, and the spelling a model gets wrong is the one a
// rule has to catch. The command words are the exception and say so themselves:
// ReadCommands and WriteCommands spell their alternations `(?-i:...)`, a program
// called CAT being a different program.
//
// Three callers compiled this themselves before, and one of them had forgotten
// the flag, which made one catalogue into two readings of it.
func Compile(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + pattern)
}

// GuardRules is a catalogue as the agent's own tools and its shell are held to
// it: a subject named at all is refused, whatever the command would do with it.
//
// Packed, one alternation per kind rather than one rule per entry. The rendered
// file is a list of patterns and nothing else, so there is no message to keep
// beside a rule and nothing a per-entry rule would buy; a host declaring 170
// paths gets three patterns rather than 340.
//
// Every line carries its kind, a whole pattern as much as a packed subject.
// That is what a refusal reads back, and it is the only thing it can read: a
// line that carried none was classified by guessing at a substring of it, so
// changing how a rule was spelled changed which message it got.
//
// In Kinds() order, which is where the order lives. First match wins on both
// tiers, so a command that is both an operator command and a named path is told
// it is an operator command, and the two sides cannot disagree about that
// without disagreeing about Kinds().
func GuardRules(rules []Rule) []string {
	subjects := make(map[Kind][]string, len(Kinds()))
	patterns := make(map[Kind][]string, len(Kinds()))
	for _, rule := range rules {
		if len(rule.Subjects) == 0 {
			patterns[rule.Kind] = append(patterns[rule.Kind], rule.Patterns...)
			continue
		}
		subjects[rule.Kind] = append(subjects[rule.Kind], rule.Subjects...)
	}
	var out []string
	for _, kind := range Kinds() {
		out = append(out, NamingAs(kind, subjects[kind])...)
		for _, pattern := range patterns[kind] {
			out = append(out, KindMarker(kind)+pattern+`)`)
		}
	}
	return out
}

// Broker is one rule as a brokered command is held to it: the whole-command
// rule for a strict entry, the readers alone otherwise.
//
// The looser reading exists so a converge can still manage a credential file, a
// keyfile rotation being a move into place. A kind with nothing to converge does
// not get it, which is why For writes every own directory strict: this side runs
// as an account of its own, or as root where an escalation was approved, and
// there is no install for a brokered command to manage. Strict is the one thing
// asked here, rather than that plus whether an entry stands behind the rule: the
// two would be two answers to one question.
//
// One rule per entry rather than packed, and no kind marker. The broker holds
// the rule beside the entry it came from, so it can name the entry and has no
// need to read a kind back out of a pattern.
func (r Rule) Broker() []string {
	if len(r.Subjects) == 0 {
		return r.Patterns
	}
	if r.Strict {
		return Naming(r.Subjects)
	}
	return Disclosing(r.Subjects)
}

// Catalogue is everything one host refuses, in the order both tiers hold it:
// the rules about faramir's own commands and files, and the rules the config
// asks for, sorted by Kinds().
//
// One function so the order is one decision. A caller that joined the two lists
// itself decided the order again, and the guard's rendered file and the broker's
// compiled set could then disagree about which of two matching rules answers.
func Catalogue(home string, ownDirs []string, secret config.SecretConfig) []Rule {
	out := append(ActionRules(), For(home, ownDirs, secret)...)
	rank := make(map[Kind]int, len(Kinds()))
	for i, kind := range Kinds() {
		rank[kind] = i
	}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Kind] < rank[out[j].Kind] })
	return out
}

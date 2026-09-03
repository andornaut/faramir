package agentcfg

// What the rendered sections say.

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/cli"
)

// What an agent is told about waiting for an escalation only holds where one can
// be raised. On any other host it describes a refusal that never happens, and
// instructions an agent cannot act on are instructions it learns to skim.
func TestTheEscalationParagraphIsWrittenOnlyOnASudoHost(t *testing.T) {
	const marker = "escalation_in_progress"
	granted, err := CredentialsSection(true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(granted, marker) {
		t.Errorf("a host with a sudo grant is not told about %s:\n%s", marker, granted)
	}
	withheld, err := CredentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withheld, marker) {
		t.Errorf("a host with no sudo grant is told about %s:\n%s", marker, withheld)
	}
	// The home says how to raise one, which holds for the same hosts and no
	// others: the grant is the host's rather than any tree's.
	const homeMarker = "Never background it"
	grantedHome, err := HomeSection(true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(grantedHome, homeMarker) {
		t.Errorf("a home on a host with a sudo grant is not told %q:\n%s",
			homeMarker, grantedHome)
	}
	withheldHome, err := HomeSection(false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withheldHome, homeMarker) {
		t.Errorf("a home on a host with no sudo grant is told %q:\n%s",
			homeMarker, withheldHome)
	}
}

// What the home section claims about the deny rules has to be true of the agent
// it is written for: pi's are compiled into the extension an enrolment
// installs, and Antigravity has nothing that refuses a file tool anything. An
// agent told it is refused everywhere, and finding it is not, has no reason to
// believe the next claim.
func TestTheHomeSectionClaimsOnlyWhatTheAgentHas(t *testing.T) {
	const everywhere = "wherever you are working"
	seen := map[bool]int{}
	for _, name := range Known() {
		target := Targets[name]
		body, err := HomeSection(true)
		if err != nil {
			t.Fatal(err)
		}
		flat := collapse(body)
		hasRules := len(target.AccountFiles) > 0
		seen[hasRules]++
		switch claims := strings.Contains(flat, everywhere); {
		case hasRules && !claims:
			t.Errorf("%s has account-wide rules and its section does not say so", name)
		case !hasRules && claims:
			t.Errorf("%s has no account-wide rules and its section says its file "+
				"tools are refused %q", name, everywhere)
		}
		// Either way the policy stands: the rules are the enforcement and this is
		// what the agent is told, and pi is told it in a tree faramir has never
		// enrolled as much as the rest are.
		if !strings.Contains(flat, "Never route around a refusal") {
			t.Errorf("%s is not told the rule that survives having no enforcement", name)
		}
	}
	// One shape now: every agent has something account-wide, so the section makes
	// the same claim for all of them. A second shape reappearing means an agent
	// was added without account-wide cover, which is what the section would then
	// have to hedge about.
	if seen[false] != 0 {
		t.Errorf("%d agent(s) have nothing account-wide, so the section cannot "+
			"claim what it claims", seen[false])
	}
}

// Each section still says what only it can, so neither is a copy of the other
// and neither depends on the other being there.
func TestEachSectionSaysWhatOnlyItCan(t *testing.T) {
	project, err := CredentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"faramir run", "faramir refs",
		"Never write a value down", "Never send one anywhere",
		"not the security\nboundary"} {
		if !strings.Contains(project, want) {
			t.Errorf("the tree's section does not say %q", want)
		}
	}
	home, err := HomeSection(true)
	if err != nil {
		t.Fatal(err)
	}
	// What a home is for. The route is named here as well as in a tree, the
	// binary reaching the broker from anywhere on the host, and saying so is the
	// point: an agent working where no enrolment ran would otherwise be refused
	// with nothing to do instead. Escalation is the home's too, the grant being
	// the host's rather than any tree's, and an agent that backgrounds the
	// command loses the approval.
	for _, want := range []string{"faramir run", "faramir refs",
		"faramir run -C", "Never background it"} {
		if !strings.Contains(home, want) {
			t.Errorf("the home section does not say %q", want)
		}
	}
	// And it does not send the agent to the operator for a value it can fetch
	// itself, which is what it had to do when the route was registered per tree.
	if strings.Contains(home, "Outside one there is no such route") {
		t.Error("the home section still says there is no route outside an enrolled " +
			"tree, which the binary makes untrue")
	}
}

// The section is prose and the route is a subcommand, so nothing but this holds
// the two together: a section that stops naming the route leaves an agent told
// it is refused and not told what to do instead, which is the shape that
// invites a workaround.
//
// The route is named rather than counted. What each command is for is the
// section's to say; that both are named at all is this.
func TestTheTreeSectionNamesTheRoute(t *testing.T) {
	body := section(t)
	for _, want := range []string{"faramir run", "faramir refs"} {
		if !strings.Contains(body, want) {
			t.Errorf("the section does not name `%s`, so a refused agent is told "+
				"nothing to do instead: agent/instructions.md.snippet", want)
		}
	}
	// And it shows one being used. A name alone leaves the model to invent the
	// flags, which is the thing a tool schema used to do for it.
	if !strings.Contains(body, "--env") {
		t.Error("the section names the route and shows no invocation of it: " +
			"agent/instructions.md.snippet")
	}
}

// The section tells the agent which faramir subcommands are its to run, and the
// guard is what enforces that: cli.Agent is the list whose arguments the guard
// leaves unscanned and cli.ReadOnly the one it allows without exempting their
// arguments, and everything else is refused to the agent's shell. A command
// named here and in neither list is one the agent is told to run and then
// refused, which is the shape that invites a workaround.
func TestTheTreeSectionNamesOnlySubcommandsTheAgentMayRun(t *testing.T) {
	body := section(t)

	// Backtick-quoted, which is how a command is written in these files: bare
	// prose naming the tool is not an instruction to run anything.
	quoted := regexp.MustCompile("`faramir ([a-z-]+(?: [a-z-]+)?)`")
	found := 0
	for _, match := range quoted.FindAllStringSubmatch(body, -1) {
		found++
		name := match[1]
		if slices.Contains(cli.Agent, name) || slices.Contains(cli.ReadOnly, name) {
			continue
		}
		// A grouped command is named in full in both lists, so a two-token match
		// that is in neither may still be a one-token command with an argument.
		if first, _, ok := strings.Cut(name, " "); ok &&
			(slices.Contains(cli.Agent, first) || slices.Contains(cli.ReadOnly, first)) {
			continue
		}
		t.Errorf("the section names `faramir %s`, which the guard refuses to the "+
			"agent's shell: cli.Agent and cli.ReadOnly are what it may run", name)
	}
	if found == 0 {
		t.Error("the section names no faramir command, so this asserts nothing")
	}
}

// And it says the rest are refused, so an agent meeting that refusal reads it
// as the policy rather than as something to get around. The clause, not the
// word: "refused" turns up elsewhere in the section.
func TestTheTreeSectionSaysTheOtherSubcommandsAreRefused(t *testing.T) {
	body := section(t)

	const clause = "Every other faramir subcommand changes the install or needs root, and is refused"
	if !strings.Contains(collapse(body), clause) {
		t.Errorf("the section does not say the commands it does not sanction are "+
			"refused:\n%s", body)
	}
}

// collapse folds a rendered paragraph onto one line, the snippets being wrapped
// prose: a clause quoted here would otherwise have to be broken where the
// snippet happens to break.
func collapse(body string) string {
	return strings.Join(strings.Fields(body), " ")
}

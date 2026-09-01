package install

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/cli"
)

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

// Both sections carry the shared rules from one snippet, so a rule changed is
// changed in both. What each may not do is claim the other's half.
func TestTheSharedRulesAreOneSnippetInBothSections(t *testing.T) {
	tree := section(t)
	home, err := agentcfg.HomeSection(true)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := agentcfg.RenderData("agent/instructions.rules.md.snippet", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimRight(string(rules), "\n")
	if body == "" {
		t.Fatal("the shared rules snippet is empty, so this asserts nothing")
	}
	for name, text := range map[string]string{"the tree's": tree, "the home's": home} {
		if !strings.Contains(text, body) {
			t.Errorf("%s section does not carry the shared rules verbatim, so the two "+
				"can drift:\n%s", name, text)
		}
	}
}

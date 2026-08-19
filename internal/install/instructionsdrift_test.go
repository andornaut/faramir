package install

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/cli"
	"github.com/andornaut/faramir/internal/mcp"
)

// The section is prose and the tools are a Go slice, so nothing but this holds
// the two together: a tool renamed leaves the section telling an agent to call
// something the server does not advertise, and a tool added leaves "Those two"
// counting wrong. Neither shows up at runtime as anything but an agent that
// gives up and runs the command itself.
func TestTheTreeSectionAndTheServerNameTheSameTools(t *testing.T) {
	body := section(t)

	if len(mcp.Tools()) == 0 {
		t.Fatal("the server advertises nothing, so this asserts nothing")
	}
	advertised := make([]string, 0, len(mcp.Tools()))
	for _, tool := range mcp.Tools() {
		advertised = append(advertised, tool.Name)
		if !strings.Contains(body, tool.Name) {
			t.Errorf("the server advertises %s and the section does not name it: "+
				"agent/instructions.md.snippet", tool.Name)
		}
	}
	for _, named := range regexp.MustCompile(`faramir_[a-z_]+`).FindAllString(body, -1) {
		if !slices.Contains(advertised, named) {
			t.Errorf("the section names %s, which the server does not advertise: "+
				"agent/instructions.md.snippet", named)
		}
	}
}

// The section tells the agent which faramir subcommands are its to run, and the
// guard is what enforces that: cli.Agent is the list whose arguments the guard
// leaves unscanned, and everything else is refused to the agent's shell. A
// command named here and absent there is one the agent is told to run and then
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
		if slices.Contains(cli.Agent, name) {
			continue
		}
		// A grouped command is named in full in cli.Agent, so a two-token match
		// that is not there may still be a one-token command with an argument.
		if first, _, ok := strings.Cut(name, " "); ok && slices.Contains(cli.Agent, first) {
			continue
		}
		t.Errorf("the section names `faramir %s`, which the guard refuses to the "+
			"agent's shell: cli.Agent is what it may run", name)
	}
	if found == 0 {
		t.Error("the section names no faramir command, so this asserts nothing")
	}
}

// And it says the rest are refused, so an agent meeting that refusal reads it
// as the policy rather than as something to get around. The clause, not the
// words: "refused" and "operator" each turn up elsewhere in the section.
func TestTheTreeSectionSaysTheOtherSubcommandsAreRefused(t *testing.T) {
	body := section(t)

	const clause = "Every other faramir subcommand is the operator's and is refused"
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
	home, err := homeSection(true)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := renderData("agent/instructions.rules.md.snippet", nil)
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

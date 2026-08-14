package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"

	faramir "github.com/andornaut/faramir"
	"github.com/andornaut/faramir/internal/mcp"
)

// renderFuncs are for templates whose output is matched against rather than
// read: the deny patterns are regexes, so an interpolated path arrives quoted.
// Unquoted, "." matches any character and a path containing "+" or "(" would
// not compile.
var renderFuncs = template.FuncMap{
	"regexQuote": regexp.QuoteMeta,
	// list is what lets one rule be written once and rendered per tool it
	// applies to.  A deny list copied per tool is a deny list that drifts, and a
	// rule that has drifted into matching nothing looks exactly like one that
	// matches everything.
	"list": func(items ...string) []string { return items },
	// The paths every agent refuses, each in that agent's own spelling.  See
	// protectedpaths.go: the list is written once in Go, and no template holds a
	// path of its own.
	"claudeRules":    claudeRules,
	"pluginPatterns": pluginPatterns,
	"jsFragments":    jsFragments,
	"installDirs":    installDirs,
	// The tools an agent is offered, for the host that has to register them
	// itself.  See mcpToolsJS.
	"mcpToolsJS": mcpToolsJS,
	// The rules both credentials sections state.  See credentialRules.
	"credentialRules": credentialRules,
	// The list emitters, so no template counts commas.
	"jsonLines":   jsonLines,
	"jsonDenyMap": jsonDenyMap,
	"quote":       jsonString,
	"tomlList":    tomlList,
}

// jsonString is one JSON string, and the only thing that should render one.
//
// Not strconv.Quote: it emits Go's escape set, and \a, \v and \xNN are none of
// them JSON.  What that renders is an agent settings file the agent cannot
// parse, so the enrolment reads as done and every rule in it is absent.  Any
// path this interpolates is the operator's, from --config-dir or --ssh-key, and
// nothing on the way here refuses a control character in one.
//
// A JSON string is also a valid TypeScript string literal, so pi's extension
// template takes the same function.
//
// SetEscapeHTML(false) so <, > and & stay literal: escaping them is valid JSON
// and changes nothing semantically, but it would rewrite every file that
// contains one for no reason.  Encode appends a newline, hence the trim.
func jsonString(text string) string {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(text); err != nil {
		// Encoding a string cannot fail; a quoted empty string keeps the rendered
		// file parseable if it ever does.
		return `""`
	}
	return strings.TrimRight(out.String(), "\n")
}

// tomlList renders a string list as a TOML array.
func tomlList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, item := range items {
		quoted = append(quoted, tomlString(item))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// tomlString is one TOML basic string.
//
// Not strconv.Quote: TOML takes a shorter set of escapes than Go, and the ones
// Go adds are rejected rather than misread.  \a and \v are the two a shell
// argument realistically carries, and either renders a config.toml the loader
// refuses, which is the failure the caller validates against precisely so it
// cannot happen after the files are written.  Everything else below \x20 goes
// out as \uXXXX, which TOML does accept.
func tomlString(text string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range text {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			// DEL as well as the C0 range: TOML allows neither raw.  A byte that is
			// not valid UTF-8 arrives here as U+FFFD, which is what ranging over a
			// string yields, and is escaped like any other rune rather than being
			// written out as an invalid sequence the loader would reject.
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&out, `\u%04X`, r)
				continue
			}
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
	return out.String()
}

// credentialRules is the part of the credentials policy both sections state:
// what must never be decrypted or read, that a refusal is not to be worked
// around, and what to do when a value arrives anyway.
//
// One asset rendered into both, rather than a paragraph written twice.  In an
// enrolled tree an agent loads both sections at once, `init` having written one
// into its home and `init-project` the other into the tree, so two copies are
// read together; copies that had drifted would read as two policies that do not
// quite agree, which is worse than reading one twice.  Neither section can
// simply drop it, either: `init` writes the home one only for the agents it
// finds or is named, and an enrolment leaves a tree's file alone when it cannot
// delimit the block, so each has to stand alone.
func credentialRules() (string, error) {
	body, err := readAsset("agent/instructions.rules.md.snippet")
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(body), "\n"), nil
}

// mcpToolsJS renders internal/mcp's tool list as a JSON object keyed by tool
// name, which is also a JavaScript object literal.
//
// pi ships no MCP and registers the same tools from the extension faramir
// installs, so without this the name, the description and the whole input
// schema of each tool are written twice and kept in step by hand.  What stays
// per-host is the label and the body that runs the tool, which is what pi
// differs in; what a model is told a tool is for does not.
//
// "parameters" rather than MCP's "inputSchema": the schema is the same document
// under the name pi's registration takes.
func mcpToolsJS(indent string) (string, error) {
	type entry struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Parameters  any    `json:"parameters"`
	}
	// Keyed by name so the template names the tool it is registering, rather
	// than indexing a list by a position this file decides.  Marshalling sorts
	// the keys, so the rendered extension is the same bytes twice.
	byName := map[string]entry{}
	for _, t := range mcp.Tools() {
		byName[t.Name] = entry{Name: t.Name, Description: t.Description, Parameters: t.InputSchema}
	}
	// An encoder rather than MarshalIndent, for SetEscapeHTML(false): the default
	// escapes ">" to ">", which JavaScript reads correctly and an operator
	// reading the installed file has to decode.
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent(indent, "  ")
	if err := enc.Encode(byName); err != nil {
		return "", fmt.Errorf("rendering the MCP tool list: %w", err)
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

// units maps each installed file name to its embedded template.  One map,
// sockets and services being written, reloaded and removed together.
var units = map[string]string{
	"faramir-broker.service": "systemd/faramir-broker.service.tmpl",
	"faramir-broker.socket":  "systemd/faramir-broker.socket.tmpl",
	"faramir-keeper.service": "systemd/faramir-keeper.service.tmpl",
	"faramir-keeper.socket":  "systemd/faramir-keeper.socket.tmpl",
	"faramir-exec.service":   "systemd/faramir-exec.service.tmpl",
	"faramir-exec.socket":    "systemd/faramir-exec.socket.tmpl",
}

// unitNames is units' keys in a fixed order.
func unitNames() []string {
	names := make([]string, 0, len(units))
	for name := range units {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// render executes one embedded template against a layout.  The templates are
// the shipped files themselves, and a field named in one and absent from Layout
// fails in the tests below rather than being ignored at runtime.
func render(assetPath string, layout Layout) ([]byte, error) {
	return renderData(assetPath, layout)
}

// renderData is render for a template whose data is not the install layout.
// The agent plugins are the case: what they need is the binary's path plus
// which agent and which file, and the last two are per-target rather than
// per-install.
func renderData(assetPath string, data any) ([]byte, error) {
	text, err := faramir.Assets.ReadFile(assetPath)
	if err != nil {
		return nil, fmt.Errorf("embedded asset %s: %w", assetPath, err)
	}
	tmpl, err := template.New(filepath.Base(assetPath)).Funcs(renderFuncs).Parse(string(text))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", assetPath, err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return nil, fmt.Errorf("%s: %w", assetPath, err)
	}
	return out.Bytes(), nil
}

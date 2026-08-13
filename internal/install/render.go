package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	// applies to.  A deny list copied per tool is a deny list that drifts, which
	// is how one of Gemini's rules came to match nothing while its siblings
	// worked.
	"list": func(items ...string) []string { return items },
	// The paths every agent refuses, each in that agent's own spelling.  See
	// protectedpaths.go: the list is written once in Go, and no template holds a
	// path of its own.
	"claudeRules":      claudeRules,
	"pluginPatterns":   pluginPatterns,
	"regexAlternation": regexAlternation,
	"jsFragments":      jsFragments,
	"installDirs":      installDirs,
	// The tools an agent is offered, for the host that has to register them
	// itself.  See mcpToolsJS.
	"mcpToolsJS": mcpToolsJS,
	// The list emitters, so no template counts commas.
	"jsonLines":   jsonLines,
	"jsonDenyMap": jsonDenyMap,
	"quote":       strconv.Quote,
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

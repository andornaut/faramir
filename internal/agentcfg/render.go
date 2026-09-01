package agentcfg

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
	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostunit"
)

// renderFuncs are for templates whose output is matched against rather than
// read: the deny patterns are regexes, so an interpolated path arrives quoted,
// "." otherwise matching any character.
var renderFuncs = template.FuncMap{
	"regexQuote": regexp.QuoteMeta,
	// marked wraps a rule this file writes by hand in the kind a refusal reads
	// back out of it. Every rendered line carries one: a line that did not was
	// classified by guessing at a substring of itself, so changing how a rule
	// was spelled changed which message it got.
	"marked": func(kind, rule string) string {
		return denyrules.KindMarker(denyrules.Kind(kind)) + rule + `)`
	},
	// list is what lets one rule be written once and rendered per tool it applies
	// to: a deny list copied per tool drifts, and a rule that has drifted into
	// matching nothing looks like one that matches everything.
	"list": func(items ...string) []string { return items },
	// The paths every agent refuses, each in that agent's own spelling. See
	// protectedpaths.go: no template holds a path of its own.
	"claudeRules":    claudeRules,
	"pluginPatterns": pluginPatterns,
	"agyRules":       agyRules,
	// The same protected set in the command guard's spelling, so a rule refuses
	// a file tool and `cat` alike. See commandRules.
	"commandRules": commandRules,
	// The write alternation, so a rule the file writes by hand for a narrower
	// subject reads the same list as the generated ones. Written out twice, they
	// drift the moment a tool is added to one. There is no read alternation:
	// naming a declared path is what refuses it, and Naming says why.
	"writeCommands": func() string { return denyrules.WriteCommands },
	"argSpan":       func() string { return denyrules.ArgSpan },
	"installDirs":   Dirs,
	// The installed binary, for an account file that has to name it. A tree's
	// files get it from PluginData; an account file renders against the layout
	// alone, and the path is the same compiled one either way.
	"binDir": func() string { return hostlayout.DefaultBinDir },
	// The rules both credentials sections state. See credentialRules.
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
// them JSON. What that renders is an agent settings file the agent cannot
// parse, so the enrolment reads as done and every rule in it is absent. A JSON
// string is also a valid TypeScript string literal, so pi's extension template
// takes the same function.
//
// SetEscapeHTML(false) so <, > and & stay literal, escaping them being valid
// JSON that would rewrite every file containing one. Encode appends a newline,
// hence the trim.
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

// tomlString is one TOML basic string. Not strconv.Quote: TOML takes a shorter
// set of escapes than Go and rejects the ones Go adds, so \a or \v in a shell
// argument would render a config.toml the loader refuses. Everything else
// below \x20 goes out as \uXXXX, which TOML accepts.
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
			// DEL as well as the C0 range: TOML allows neither raw. A byte that is
			// not valid UTF-8 arrives as U+FFFD and is escaped like any other
			// rune.
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
// One asset rendered into both. In an enrolled tree an agent loads both
// sections at once, so copies that had drifted would read as two policies that
// do not quite agree. Neither section can drop it: `init` writes the home one
// only for the agents it finds, and an enrolment leaves a tree's file alone
// when it cannot delimit the block, so each has to stand alone.
func credentialRules() (string, error) {
	body, err := Asset("agent/instructions.rules.md.snippet")
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(body), "\n"), nil
}

// Units maps each installed file name to its embedded template. One map,
// sockets and services being written, reloaded and removed together.
var Units = map[string]string{
	hostunit.BrokerUnit:     "systemd/faramir-broker.service.tmpl",
	"faramir-broker.socket": "systemd/faramir-broker.socket.tmpl",
	hostunit.KeeperUnit:     "systemd/faramir-keeper.service.tmpl",
	"faramir-keeper.socket": "systemd/faramir-keeper.socket.tmpl",
	hostunit.ExecUnit:       "systemd/faramir-exec.service.tmpl",
	"faramir-exec.socket":   "systemd/faramir-exec.socket.tmpl",
}

// UnitNames is units' keys in a fixed order.
func UnitNames() []string {
	names := make([]string, 0, len(Units))
	for name := range Units {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// RenderAccount renders one account file. These read the layout the way every
// other asset does, and one that is a program also names the binary it execs
// and the dialect it speaks, so they render against the same data a tree's
// files do rather than against the bare layout.
func RenderAccount(assetPath string, layout hostlayout.Layout) ([]byte, error) {
	return RenderData(assetPath, PluginData{BinDir: hostlayout.DefaultBinDir, Layout: layout})
}

// Render executes one embedded template against a layout. The templates are
// the shipped files themselves, and a field named in one and absent from Layout
// fails the tests rather than being ignored at runtime.
func Render(assetPath string, layout hostlayout.Layout) ([]byte, error) {
	return RenderData(assetPath, layout)
}

// RenderData is render for a template whose data is not the install layout: the
// agent plugins need the binary's path plus which agent and which file, and the
// last two are per-target rather than per-install.
func RenderData(assetPath string, data any) ([]byte, error) {
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

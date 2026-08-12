package install

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"text/template"

	faramir "github.com/andornaut/faramir"
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

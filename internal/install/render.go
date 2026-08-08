package install

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"text/template"

	faramir "github.com/andornaut/faramir"
)

// units maps each installed file name to its embedded template.  The sockets
// and the services are one map because they are written, reloaded and removed
// together; nothing reads one without the other.
var units = map[string]string{
	"faramir-broker.service": "systemd/faramir-broker.service.tmpl",
	"faramir-broker.socket":  "systemd/faramir-broker.socket.tmpl",
	"faramir-keeper.service": "systemd/faramir-keeper.service.tmpl",
	"faramir-keeper.socket":  "systemd/faramir-keeper.socket.tmpl",
	"faramir-exec.service":   "systemd/faramir-exec.service.tmpl",
	"faramir-exec.socket":    "systemd/faramir-exec.socket.tmpl",
}

// unitNames is units' keys in a fixed order, so a run's output and its steps do
// not reshuffle between invocations.
func unitNames() []string {
	names := make([]string, 0, len(units))
	for name := range units {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// render executes one embedded template against a layout.
//
// The templates are the shipped files themselves rather than a separate set,
// so what is read to understand the install is what the install writes.  A
// field named in one and absent from Layout is a build-time failure in the
// tests below, not a directive systemd silently ignores at runtime.
func render(assetPath string, layout Layout) ([]byte, error) {
	text, err := faramir.Assets.ReadFile(assetPath)
	if err != nil {
		return nil, fmt.Errorf("embedded asset %s: %w", assetPath, err)
	}
	tmpl, err := template.New(filepath.Base(assetPath)).Parse(string(text))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", assetPath, err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, layout); err != nil {
		return nil, fmt.Errorf("%s: %w", assetPath, err)
	}
	return out.Bytes(), nil
}

package config

import (
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"

	faramir "github.com/andornaut/faramir"
)

// documentedKey matches the way the shipped prose names a setting: the section
// in brackets, then the key, either or both in backticks. A markdown link is
// not this, its bracketed part being followed by a parenthesis rather than by a
// word, and `[[secret.link]]` is not either, the inner bracket being followed
// by the outer one.
var documentedKey = regexp.MustCompile("\\[([a-z.]+)\\][ \t]+`?([a-z_]+)`?")

// A key the loader does not accept is refused as unknown, so a document naming
// one is describing a config that would stop the daemons rather than configure
// them. The failure is silent in both directions: prose is not compiled, and a
// key renamed in the loader leaves every mention of the old name reading as
// though it still worked.
//
// Over the embedded docs, which is what installs onto a host and what an
// operator reads there.
func TestEverySettingTheDocsNameIsOneTheLoaderAccepts(t *testing.T) {
	byName := map[string][]string{
		"server": serverKeys, "keeper": keeperKeys, "executor": executorKeys,
		"command": commandKeys, "ssh": sshKeys, "escalation": escalationKeys,
		"secret": secretKeys, "audit": auditKeys,
	}
	// Every section the loader knows has an entry above, or a document could
	// name a key in the one section nothing here checks.
	for _, section := range sections {
		if _, ok := byName[section]; !ok {
			t.Errorf("[%s] is a section the loader accepts and this test does not "+
				"check", section)
		}
	}

	checked := 0
	for _, name := range shippedDocs(t) {
		body, err := fs.ReadFile(faramir.Assets, name)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range documentedKey.FindAllStringSubmatch(string(body), -1) {
			section, key := match[1], match[2]
			// [command.env] holds whatever an operator names with --command-env.
			if section == "command.env" {
				continue
			}
			keys, known := byName[section]
			if !known {
				continue
			}
			checked++
			if !slices.Contains(keys, key) {
				t.Errorf("%s names `[%s] %s`, which the loader refuses as an unknown "+
					"key: it accepts %v", name, section, key, keys)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the docs name no setting, so this asserts nothing")
	}
}

// shippedDocs is every markdown file that installs onto a host.
func shippedDocs(t *testing.T) []string {
	t.Helper()
	var out []string
	err := fs.WalkDir(faramir.Assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no markdown is embedded, so this asserts nothing")
	}
	return out
}

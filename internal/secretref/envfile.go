package secretref

// The refs a run builds its environment from: the --env flags and the
// --env-file files, and what an entry in either may spell.

import (
	"fmt"
	"maps"
	"os"
	"strings"
)

// noConflict records name=uri unless the map already carries the name with a
// different ref. Not last-wins: silently picking one of two is how the wrong
// credential reaches a host. An identical repeat is a merge artefact, so it
// passes. where prefixes the refusal with the place the caller is reading.
func noConflict(refs map[string]string, where, name, uri string) error {
	if existing, seen := refs[name]; seen && existing != uri {
		return fmt.Errorf("%s%s is given twice, as %s and %s", where, name, existing, uri)
	}
	refs[name] = uri
	return nil
}

// EnvRefs is what a command's environment is built from: every --env-file in
// the order it was given, and then every --env. A --env overrides a file that
// names the same variable, by design: a flag is the near edit to a file's
// defaults. But two files, or two --env flags, that name one variable with two
// different refs are an ambiguity nothing resolves, and silently picking one is
// how the wrong credential reaches a host: those are refused, the same as a
// name given twice inside one file. Its own function so the rule can be asserted
// without a broker to run a command against.
func EnvRefs(envFiles, envRefs []string) (map[string]string, error) {
	refs := map[string]string{}
	for _, path := range envFiles {
		pairs, err := readEnvFile(path)
		if err != nil {
			return nil, err
		}
		for name, uri := range pairs {
			if err := noConflict(refs, "--env-file: ", name, uri); err != nil {
				return nil, err
			}
		}
	}
	// The flags are their own layer: they override a file, but among themselves
	// the same conflict is refused, so they are gathered apart and merged on top.
	flags := map[string]string{}
	for _, pair := range envRefs {
		name, uri, ok := strings.Cut(pair, "=")
		if !ok {
			// A name on its own, the same shortcut a bare --env-file line is. Not
			// taken on trust: checkEnv holds it to what an environment variable may
			// be called and to what a ref may be, so a word that is neither is
			// refused rather than becoming a ref nothing serves.
			name, uri = pair, "faramir://"+pair
		}
		if err := checkEnv(name, uri); err != nil {
			return nil, fmt.Errorf("--env %w", err)
		}
		if err := noConflict(flags, "--env ", name, uri); err != nil {
			return nil, err
		}
	}
	maps.Copy(refs, flags)
	return refs, nil
}

// checkEnv validates one NAME=faramir://ref pair, for both --env and
// --env-file. The error names the variable and never quotes the value: a
// pasted credential is the mistake this exists to prevent, and echoing one puts
// it in the scrollback.
func checkEnv(name, uri string) error {
	if !ValidEnvName(name) {
		// Cutting on "=" would name the variable "export NAME".
		if strings.HasPrefix(name, "export ") {
			return fmt.Errorf("%q is not a usable environment variable name; "+
				`drop the "export", this is not a shell script`, name)
		}
		// A bare name that is a usable ref and not a usable variable name, which
		// is every ref with a "/" in it and so most of them. The shortcut cannot
		// carry one: it names the variable and the ref with one word, and here
		// they cannot be the same word. Said with the long form, that being what
		// somebody reaching for the shortcut wanted.
		if uri == "faramir://"+name {
			if _, err := Parse(uri); err == nil {
				return fmt.Errorf("%q is a ref, not a valid variable name. The short "+
					"form uses one word for both, so this ref needs a variable name "+
					"of its own: --env NAME=%s", name, uri)
			}
		}
		return fmt.Errorf("%q is not a usable environment variable name", name)
	}
	if !strings.HasPrefix(uri, "faramir://") {
		// The example is written out rather than built from what arrived. What
		// arrived is either a bare ref, which the example already shows how to
		// spell, or a pasted value, and quoting that back would put it in the
		// output this exists to keep it out of.
		return fmt.Errorf("%s must be a faramir:// reference, never a value: "+
			"--env %s=faramir://<ref>. `faramir refs` lists the refs", name, name)
	}
	// The ref itself, not only the scheme. The two namespaces are not the same
	// shape: an environment variable may open with an underscore and a ref may
	// not, so a bare `_NAME` line is a usable variable name whose ref no store
	// can hold. Blocked here, with the file and the line, rather than at the
	// broker with the line long gone.
	if _, err := Parse(uri); err != nil {
		return fmt.Errorf("%s names %s, which is not a valid ref: "+
			"letters, digits, and then any of . _ - /", name, uri)
	}
	return nil
}

// dropComment cuts a trailing comment: a "#" that follows whitespace, as one
// does in a shell and in most dotenv readers. The whitespace is required, and is
// what keeps this unambiguous. Elsewhere a "#" may be part of a value, and the
// quoting rules that tell those apart are the awkward half of every such parser;
// the right of a line here is a ref, which cannot hold one.
//
// A malformed ref can, though, and cutting "faramir://api#token" at the "#" would
// leave "faramir://api", which may be a ref that exists and holds another
// credential. Written without a space it stays whole and is refused as what it is.
func dropComment(line string) string {
	// From 1: a leading "#" is a whole-line comment, and the caller took it.
	for i := 1; i < len(line); i++ {
		if line[i] == '#' && (line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

// readEnvFile reads NAME=faramir://ref lines, one per line. A line that is only a
// name asks for the ref of that name, NAME meaning NAME=faramir://NAME: naming a
// credential after the variable that carries it is the ordinary case, and writing
// both halves out says the same word twice in the one file that says which
// credentials a run needs.
//
// A comment runs to the end of the line, whole-line or after whitespace; see
// dropComment.
//
// The file holds refs and never values, so it lives beside the playbook it
// belongs to.
func readEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--env-file %s: %w", path, err)
	}
	refs := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(dropComment(line))
		name, uri, ok := strings.Cut(line, "=")
		if !ok {
			// A name on its own. Not taken on trust: checkEnv below holds it to
			// what an environment variable may be called, so a line that is not a
			// name at all is refused, naming this file and this line.
			name, uri = line, "faramir://"+line
		}
		name, uri = strings.TrimSpace(name), strings.TrimSpace(uri)
		// Checked here so the message can name the file and the line.
		if err := checkEnv(name, uri); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		if err := noConflict(refs, fmt.Sprintf("%s:%d: ", path, i+1), name, uri); err != nil {
			return nil, err
		}
	}
	return refs, nil
}

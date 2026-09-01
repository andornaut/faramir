package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/secretlink"
	"github.com/andornaut/faramir/internal/secretref"
)

// Link is one secret the broker reads from a file outside the managed store: an
// API token in a tool's own dotfile, kept where that tool expects it so that
// rotating it is that tool's business.
//
// The broker reads these, not the keeper: a linked file needs no age key, and
// the keeper runs with the homes taken away entirely, while the broker already
// holds every plaintext value and sees the homes to stat a request's cwd.
//
// One entry is one ref with one selector. Flattening a whole file would put
// its ordinary strings in the value set, and a registry URL is long enough to
// clear min_length and common enough to turn unrelated output into tokens.
type Link struct {
	// Ref is the name a caller asks by, in the same flat namespace the sops store
	// uses. Nothing marks a ref as linked, or moving one into the store later
	// would rename it.
	Ref string `json:"ref"`
	// Path is the file, absolute. No "~": a config file has no home to expand.
	Path string `json:"path"`
	// Type is how the file is read. See internal/secretlink.
	Type string `json:"type"`
	// Key selects one value out of a structured file, and is required for exactly
	// the types that select.
	Key string `json:"key,omitempty"`
	// Strict refuses every command naming this file rather than the ones
	// that would print it. See BlockedPath.Strict: one flag,
	// one meaning, on whichever entry names the file.
	Strict bool `json:"strict,omitempty"`
}

// BlockedPath is a file the agent's own tools are refused and faramir does not
// read: a LUKS keyfile, an SSH identity, anything whose value it has no use
// for. Named in full or by a pattern, which are Path and Name: exactly one of
// them, an entry saying both being two rules written as one.
//
// The two forms are not interchangeable. A path refuses the file at that path
// on this host. A name refuses every file whose name matches, wherever it
// turns up, which is what reaches a path this host does not have: a container
// mounts /srv/ha/config as /config, and the agent names the second, so a rule
// carrying the first covers nothing it runs.
//
// The weaker half of the pair, and deliberately so. A [[secret.link]] entry
// regroups its file to the broker's group, so a brokered command is refused it
// too, and puts the value in the redactor, so the value is tokenised wherever
// it turns up. This does neither: it renders one deny rule into each agent's
// rule file and stops there. A command the broker runs may still open the file
// if its mode allows, and what it prints is in the clear, there being no value
// in the redactor to match.
//
// That is the trade it exists for. Reading the value would mean holding it,
// and these are the files whose value faramir should never hold.
type BlockedPath struct {
	// Path is the file or directory, absolute. No "~", for the reason a link's
	// path carries none: nothing expands one here.
	Path string `json:"path,omitempty"`
	// Command is a command the agent's shell may not run, written the way it
	// would be typed: "op read", "sops -d". Not a path and not a pattern, so it
	// reaches the command guard alone and no agent's file-tool rules.
	//
	// The words, not a regular expression. Everything in it is taken literally
	// and the spaces between the words match any run of whitespace, so an
	// operator declares what they mean without a language in between and cannot
	// write one that matches more than it looks like.
	Command string `json:"command,omitempty"`

	// Strict refuses every command naming this path or matching this name,
	// rather than the ones that would print it. Off by default,
	// because the default has to be the one that leaves a host working: a
	// declared file usually still has to be managed, and a LUKS keyfile that
	// nothing may chmod is a key nothing may rotate either.
	//
	// It is for the directory the agent has no business in at all, ~/.private
	// and its kind, where `ls` is as unwelcome as `cat` and the operator would
	// rather meet a refusal than wonder. The cost is what it says: a command
	// naming the path for any reason is refused, so nothing converges it any
	// more.
	//
	// Not for a command entry, which is already about what a command does: an
	// entry may not carry both.
	Strict bool `json:"strict,omitempty"`
}

// Blocks is what an entry names, whichever form it took, for a message or a
// listing that wants one string.
func (r BlockedPath) Blocks() string {
	if r.Command != "" {
		return r.Command
	}
	return r.Path
}

// BaseLinks is the links this install declares, for a caller about to rewrite
// the file. A file that is not there yields nothing, which is a first
// install.
func BaseLinks(path string) ([]Link, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return cfg.Secret.Links, nil
}

// BaseBlocked is the blocked paths this install declares, for a caller about to
// rewrite the file. A file that is not there yields nothing, which is a first
// install.
func BaseBlocked(path string) ([]BlockedPath, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return cfg.Secret.Blocked, nil
}

// ValidateLink holds one entry to what the loader would accept, for a command
// that builds one before anything writes it.
func ValidateLink(link Link) error { return validateLink(link, "[[secret.link]]") }

// The entry tables inside [secret], which are not sections of their own.
var (
	linkKeys  = []string{"ref", keyPath, "type", keyKey, keyStrict}
	blockKeys = []string{keyPath, keyCommand, keyStrict}
)

// loadLinks validates every [[secret.link]] entry. Checked at load rather than
// where the file is read, so a typo stops the daemon rather than surfacing
// later as a value the redactor turns out not to have.
func loadLinks(value any, where string) ([]Link, error) {
	if value == nil {
		return nil, nil
	}
	entries, ok := value.([]map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected [[secret.link]] tables, got %T "+
			"(write each entry as its own [[secret.link]] header)", where, value)
	}
	out := make([]Link, 0, len(entries))
	seen := map[string]bool{}
	for i, entry := range entries {
		at := fmt.Sprintf("%s: [[secret.link]] #%d", where, i+1)
		if err := rejectUnknownKeys(entry, linkKeys, at); err != nil {
			return nil, err
		}
		link := Link{}
		var err error
		if link.Ref, err = str(entry["ref"], at, ""); err != nil {
			return nil, err
		}
		if link.Path, err = str(entry["path"], at, ""); err != nil {
			return nil, err
		}
		if link.Type, err = str(entry["type"], at, ""); err != nil {
			return nil, err
		}
		if link.Key, err = str(entry["key"], at, ""); err != nil {
			return nil, err
		}
		if link.Strict, err = boolean(entry[keyStrict], at, keyStrict, false); err != nil {
			return nil, err
		}
		if err := validateLink(link, at); err != nil {
			return nil, err
		}
		// A ref is the name a caller asks by, so two entries claiming one is
		// refused rather than resolved.
		if seen[link.Ref] {
			return nil, fmt.Errorf("%s: ref %q is claimed by more than one entry; "+
				"a ref has one definition", at, link.Ref)
		}
		seen[link.Ref] = true
		out = append(out, link)
	}
	return out, nil
}

// loadBlocked validates every [[secret.block]] entry. Held to the same rules a
// link's path is, minus everything about reading the file: there is no type, no
// key and no ref, because nothing is read out of it.
//
// A path that is not there is accepted. These are keys on volumes that are not
// always mounted, and a deny rule costs nothing while the file is absent, so
// refusing one would mean refusing the case the feature exists for.
func loadBlocked(value any, where string) ([]BlockedPath, error) {
	if value == nil {
		return nil, nil
	}
	entries, ok := value.([]map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected [[secret.block]] tables, got %T "+
			"(write each entry as its own [[secret.block]] header)", where, value)
	}
	out := make([]BlockedPath, 0, len(entries))
	seen := map[string]bool{}
	for i, entry := range entries {
		at := fmt.Sprintf("%s: [[secret.block]] #%d", where, i+1)
		// CLEANUP (added 2026-08-29): the name form is gone. Answered here, ahead
		// of rejectUnknownKeys and without "name" among the keys it advertises, so
		// that an operator is never shown the form as valid and then refused for
		// writing it. Remove once no config on this host declares one.
		if removed, err := str(entry["name"], at, ""); err != nil {
			return nil, err
		} else if removed != "" {
			return nil, fmt.Errorf("%s: name %q, and the name form has been removed. "+
				"A name matched a pattern against every file on the host, which "+
				"refused ordinary files and missed credential ones. Declare the "+
				"file or the directory with a path entry instead, which is exact",
				at, Shown(removed))
		}
		if err := rejectUnknownKeys(entry, blockKeys, at); err != nil {
			return nil, err
		}
		refused := BlockedPath{}
		var err error
		if refused.Path, err = str(entry["path"], at, ""); err != nil {
			return nil, err
		}
		if refused.Command, err = str(entry[keyCommand], at, ""); err != nil {
			return nil, err
		}
		if refused.Strict, err = boolean(entry[keyStrict], at, keyStrict, false); err != nil {
			return nil, err
		}
		if err := validateBlocked(refused, at); err != nil {
			return nil, err
		}
		// Two entries naming one path render one rule, so the second is an
		// operator who thinks something more was added. Keyed on the form as well
		// as the value: a path and a command that read alike are two different
		// rules.
		key := "path\x00" + refused.Path
		if refused.Command != "" {
			key = "command\x00" + refused.Command
		}
		if seen[key] {
			return nil, fmt.Errorf("%s: %q is named by more than one entry",
				at, Shown(refused.Blocks()))
		}
		seen[key] = true
		out = append(out, refused)
	}
	return out, nil
}

// ValidateBlocked holds one entry to what the loader would accept, for a
// command that builds one before anything writes it.
func ValidateBlocked(refused BlockedPath) error {
	return validateBlocked(refused, "[[secret.block]]")
}

// validateBlocked sends an entry to the rules for the form it took, and refuses
// one that took both or neither. Neither is an empty entry rendering nothing;
// both is one entry asking for two rules, and answering it by picking a form
// would render the one the operator was not looking at.
func validateBlocked(blocked BlockedPath, at string) error {
	var named []string
	for _, form := range []struct{ key, value string }{
		{"path", blocked.Path}, {"command", blocked.Command},
	} {
		if form.value != "" {
			named = append(named, fmt.Sprintf("%s %q", form.key, form.value))
		}
		if err := refuseControl(form.key, form.value, at); err != nil {
			return err
		}
	}
	switch {
	case len(named) > 1:
		return fmt.Errorf("%s: names %s, and an entry is one of them: a path blocks "+
			"that file here and a command blocks a command. Write an entry each",
			at, strings.Join(named, " and "))
	case blocked.Command != "":
		// A command entry is already about what a command does, so there is no
		// looser reading of it for this to tighten: strict narrows what a
		// brokered command may do to a declared file, and this entry names no
		// file. Refused rather than ignored: an entry carrying it means to close
		// something, and accepting it while changing nothing leaves an operator
		// sure they did.
		if blocked.Strict {
			return fmt.Errorf("%s: %s narrows what a brokered command may do to a "+
				"declared file, and this entry names a command rather than a file. "+
				"A command entry is already refused to the agent's shell and to a "+
				"brokered command alike. Drop the key", at, keyStrict)
		}
		return validateBlockedCommand(blocked.Command, at)
	}
	return validateBlockedPath(blocked, at)
}

// validateBlockedCommand holds a command entry to what can be rendered. The
// words are taken literally, so there is no pattern to get wrong; what is left
// to check is that each word is long enough to mean one.
//
// An empty command is not checked here: validateBlocked reaches this only for a
// non-empty one, and an entry naming nothing at all is refused there as naming
// no form.
//
// A single letter would match every command carrying it as a word, which is
// most of them, and is the same failure "/" is as a path.
func validateBlockedCommand(command, at string) error {
	if strings.TrimSpace(command) != command {
		return fmt.Errorf("%s: command %q is padded with whitespace", at, Shown(command))
	}
	for word := range strings.FieldsSeq(command) {
		if len(word) < 2 {
			return fmt.Errorf("%s: command %q carries the single-character word %q, "+
				"which matches nearly every command line. Write the command as it "+
				"would be typed", at, Shown(command), Shown(word))
		}
	}
	return nil
}

func validateBlockedPath(refused BlockedPath, at string) error {
	if refused.Path == "" {
		return fmt.Errorf("%s: path or command is required; one of them is "+
			"the whole of the entry", at)
	}
	return validateRulePath(refused.Path, at)
}

// validateRulePath holds a path to what a deny rule can carry. Both forms that
// render one are held to it: a blocked path and a linked path reach the same
// subject and the same rules, so a spelling that renders a rule matching nothing
// is the same fault whichever wrote it.
func validateRulePath(path, at string) error {
	if strings.HasPrefix(path, "~") {
		return fmt.Errorf("%s: path %q starts with ~, which nothing expands here. "+
			"Write the path in full", at, Shown(path))
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s: path %q is relative, and a deny rule is matched "+
			"against a path the agent names in full. Write it in full", at, Shown(path))
	}
	// A rule is a literal string in someone else's config, so the path that
	// reaches it has to be the one an agent would name. "/etc/./k" and "/etc/k"
	// are one file and would be two rules, one of which matches nothing. The
	// file still opens either way, so a link written this way works while the
	// rule rendered from it protects nothing.
	if clean := filepath.Clean(path); clean != path {
		return fmt.Errorf("%s: path %q is not in its shortest form, and a deny rule "+
			"matches the path as written. Use %q", at, Shown(path), Shown(clean))
	}
	// "/" would render a rule refusing the whole filesystem, which fails closed
	// and leaves the agent unable to read anything at all.
	if path == "/" {
		return fmt.Errorf("%s: path is /, which would refuse the agent every file "+
			"on the host. Name the file or the directory that holds it", at)
	}
	// One wildcard is accepted and only in one place: a trailing "*" on the last
	// component, after at least one literal character. That form names a file
	// whose name this config cannot write in full -- a sentry carrying a
	// per-account number, a dated key -- and it renders a rule that matches the
	// name as it appears rather than the pattern as it is typed.
	//
	// Every other placement is refused. A path is otherwise matched as a literal,
	// so a wildcard in one is not expanded: it renders a rule that refuses a
	// command typing that same pattern and leaves every file the pattern names
	// readable. Refused rather than accepted, because an operator writing it
	// believes the files are blocked, and a rule covering nothing reads exactly
	// like one covering everything.
	//
	// The bound is what keeps the accepted form from being the refused one under
	// another name. The literal parent decides the blast radius, so "*/token" and
	// "*.json" stay out: the first names a directory this cannot know and the
	// second names every such file on the host. A bare "<dir>/*" is out for the
	// same reason it always was -- the directory is what to name, and an entry
	// covers everything under it, including the files added later.
	//
	// And the parent has to be a directory rather than the root. "/h*" otherwise
	// passes every check above it -- absolute, clean, not "/", a literal
	// character before the wildcard -- and renders a rule that reaches /home and
	// /etc alike, which is the outcome the "/" check exists to prevent. A
	// top-level prefix has no literal parent to bound it, so there is nothing for
	// the blast radius to be measured against.
	if literal, isPrefix := strings.CutSuffix(path, "*"); isPrefix &&
		!strings.HasSuffix(literal, "/") && !strings.ContainsAny(literal, globChars) {
		if filepath.Dir(literal) == "/" {
			return fmt.Errorf("%s: path %q opens a top-level name, and a rule is not "+
				"anchored on the left: it would reach every directory under / whose "+
				"name begins that way. Name a directory first, so the literal parent "+
				"bounds what the wildcard can reach", at, Shown(path))
		}
		return nil
	}
	if i := strings.IndexAny(path, globChars); i >= 0 {
		return fmt.Errorf("%s: path %q carries %q, and a path is matched as written "+
			"rather than expanded: the rule would refuse a command typing that "+
			"pattern and leave the files it names readable. The one wildcard a path "+
			"may carry is a trailing %q after at least one literal character of the "+
			"last component. Otherwise name the directory that holds them, which "+
			"covers everything under it",
			at, Shown(path), string(path[i]), "*")
	}
	return nil
}

// globChars are what a shell expands. A file whose name really carries one is
// reachable by naming the directory that holds it, which is the advice the
// refusal gives anyway.
const globChars = `*?[`

func validateLink(link Link, at string) error {
	// The same pattern a faramir:// URI is parsed against: a ref outside it would
	// load and then be unreachable.
	if link.Ref == "" {
		return fmt.Errorf("%s: ref is required; it is the name a caller asks by", at)
	}
	if !secretref.Valid(link.Ref) {
		return fmt.Errorf("%s: ref %q is not a name a faramir:// reference can carry; "+
			"letters, digits, and then any of . _ - /", at, Shown(link.Ref))
	}
	if link.Path == "" {
		return fmt.Errorf("%s: path is required", at)
	}
	// The path is rendered into the agents' deny rules and into the guard's, so
	// it carries the same hazard a blocked entry does: one rule per line, and a
	// newline in the subject splits the rule into two fragments that will not
	// compile and are skipped. The key never reaches a rule, and is held to the
	// same bytes because both are printed back by `faramir link ls`.
	if err := refuseControl("path", link.Path, at); err != nil {
		return err
	}
	if err := refuseControl("key", link.Key, at); err != nil {
		return err
	}
	// The same checks a blocked path gets: this one renders into the same rules,
	// so a spelling that renders a rule matching nothing is the same fault here.
	// A link opens the file it names -- `link add` stats it, and the store stats
	// it again on every load -- so the trailing-wildcard form a blocked path may
	// carry is refused here. It would render a rule and never resolve a value,
	// which is a ref that is permanently degraded: `faramir doctor` reports it
	// and the exit status is non-zero, for an entry that loaded cleanly.
	//
	// Checked before validateRulePath so the refusal says why a link differs,
	// rather than the shared message offering a form this side cannot use.
	if _, isPrefix := strings.CutSuffix(link.Path, "*"); isPrefix {
		return fmt.Errorf("%s: path %q ends in a wildcard, and a link opens the file "+
			"it names rather than matching text: the ref would never resolve. Name "+
			"the file. A [[secret.block]] entry is what may carry that form", at,
			Shown(link.Path))
	}
	if err := validateRulePath(link.Path, at); err != nil {
		return err
	}
	if link.Type == "" {
		return fmt.Errorf("%s: type is required; one of %s", at,
			strings.Join(secretlink.Kinds(), ", "))
	}
	if !slices.Contains(secretlink.Kinds(), link.Type) {
		return fmt.Errorf("%s: unknown type %q; one of %s", at, link.Type,
			strings.Join(secretlink.Kinds(), ", "))
	}
	// Required and refused, rather than ignored where it means nothing: a key on
	// a whole-file link is an operator who believes something is being
	// selected.
	if secretlink.NeedsKey(link.Type) && link.Key == "" {
		return fmt.Errorf("%s: type %q selects one value out of the file, so key is "+
			"required", at, link.Type)
	}
	if !secretlink.NeedsKey(link.Type) && link.Key != "" {
		return fmt.Errorf("%s: type %q is the whole file, so key selects nothing; "+
			"remove it, or name a type that selects: %s", at, link.Type,
			strings.Join(selectingKinds(), ", "))
	}
	return nil
}

// selectingKinds is the types that take a key, for the message above.
func selectingKinds() []string {
	var out []string
	for _, kind := range secretlink.Kinds() {
		if secretlink.NeedsKey(kind) {
			out = append(out, kind)
		}
	}
	return out
}

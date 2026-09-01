package config

import (
	"strings"
	"testing"
)

// The one wildcard a path entry may carry: a trailing "*" on the last
// component, after at least one literal character. It exists for a file whose
// name a config cannot write in full, a sentry carrying a per-account number
// among them, and the literal parent is what bounds what it can reach.
func TestATrailingWildcardOnTheLastComponentLoads(t *testing.T) {
	for name, path := range map[string]string{
		"a sentry file":   "/home/op/.local/share/Steam/ssfn*",
		"a dated key":     "/home/op/.config/app/key-2026*",
		"one character":   "/home/op/.config/app/k*",
		"under /etc":      "/etc/app/session*",
		"a dotted prefix": "/home/op/.config/app/.env*",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(t, minimal+"\n[[secret.block]]\npath = \""+path+"\"\n")
			if err != nil {
				t.Fatalf("refused %q, and it is the accepted form: %v", path, err)
			}
			if len(cfg.Secret.Blocked) != 1 || cfg.Secret.Blocked[0].Path != path {
				t.Errorf("loaded %+v, want the one entry naming %q", cfg.Secret.Blocked, path)
			}
		})
	}
}

// Every other placement stays refused. A wildcard that is not a trailing one on
// the last component either names a directory this cannot know or reaches every
// such file on the host, and the refusal has to say which form is the accepted
// one rather than only that this is not it.
func TestAWildcardAnywhereElseIsStillRefused(t *testing.T) {
	for name, path := range map[string]string{
		// The directory is what to name, and it covers the files added later.
		"a bare last component": "/home/op/.local/share/Steam/*",
		// A directory this entry cannot know, and one that is every such file.
		"a middle component": "/home/op/.config/*/token",
		"an extension":       "/home/op/.config/app/*.json",
		// A wildcard with a literal after it is not the accepted form: the rule
		// would be matched as written and refuse nothing the operator meant.
		"a leading wildcard": "/home/op/.config/app/*.env",
		"an inner wildcard":  "/home/op/.config/app/a*b",
		// The other two characters a shell expands, in any position.
		"a question mark":   "/home/op/.config/app/key?",
		"a character class": "/home/op/.config/app/key[12]",
		"two wildcards":     "/home/op/.config/app/a*b*",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, minimal+"\n[[secret.block]]\npath = \""+path+"\"\n")
			if err == nil {
				t.Fatalf("loaded %q, and it is not the accepted form", path)
			}
			if !strings.Contains(err.Error(), "trailing") {
				t.Errorf("error is %q, want it to name the accepted form", err)
			}
		})
	}
}

// A link does not take the form, and that is the one place the two entry kinds
// read a path differently. A link opens the file it names, so a wildcard there
// renders a rule and never resolves a value: the ref loads and is permanently
// degraded, which doctor reports and the exit status carries.
func TestALinkPathRefusesTheWildcardABlockAccepts(t *testing.T) {
	const path = "/home/op/.config/app/token*"
	body := "[[secret.link]]\nref = \"a/b\"\npath = \"" + path + "\"\ntype = \"text\"\n"
	_, err := load(t, minimal+"\n"+body)
	if err == nil {
		t.Fatal("loaded a trailing wildcard on a link path, and a link opens the file")
	}
	if !strings.Contains(err.Error(), "never resolve") {
		t.Errorf("error is %q, want it to say the ref would not resolve", err)
	}
	// The same path as a block entry, which is what the refusal points at.
	if _, err := load(t, minimal+"\n[[secret.block]]\npath = \""+path+"\"\n"); err != nil {
		t.Fatalf("refused the same path as a block entry: %v", err)
	}
}

// A top-level prefix has no literal parent to bound it. Path rules are not
// anchored on the left, so "/h*" renders a rule reaching /home and /etc alike,
// which is what the "/" check above it exists to prevent.
func TestATopLevelPrefixIsRefused(t *testing.T) {
	for _, path := range []string{"/h*", "/e*", "/home*"} {
		t.Run(path, func(t *testing.T) {
			_, err := load(t, minimal+"\n[[secret.block]]\npath = \""+path+"\"\n")
			if err == nil {
				t.Fatalf("loaded %q, and it reaches every top-level name opening that way", path)
			}
			if !strings.Contains(err.Error(), "top-level") {
				t.Errorf("error is %q, want it to name the bound that is missing", err)
			}
		})
	}
	// One component deeper is the accepted form: the parent is a directory, and
	// it is what decides how far the wildcard reaches.
	if _, err := load(t, minimal+"\n[[secret.block]]\npath = \"/etc/shadow*\"\n"); err != nil {
		t.Fatalf("refused a prefix whose parent is a directory: %v", err)
	}
}

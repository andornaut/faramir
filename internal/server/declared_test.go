package server

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sockutil"
)

// blocking is a check over the entries a host declares, with no home to expand
// a "~" against: the spellings that need one are the agent's own shell's, and
// this is the brokered route.
func blocking(entries ...config.BlockedPath) declaredCheck {
	return newDeclaredCheck(config.SecretConfig{Blocked: entries}, "")
}

// linking is the same for a [[secret.link]] entry, which is held to the same
// rule: the file holds more than the one ref a link selects, and the rest of it
// is in no redactor.
func linking(links ...config.Link) declaredCheck {
	return newDeclaredCheck(config.SecretConfig{Links: links}, "")
}

func pathEntry(path string) config.BlockedPath { return config.BlockedPath{Path: path} }
func nameEntry(name string) config.BlockedPath { return config.BlockedPath{Name: name} }

// The hole this closes. A blocked path is refused to the agent's file tools and
// to its shell, and neither rule reaches the broker: the guard is a hook over
// shell tools, and an MCP faramir_run call is not one. So the one route the
// agent has left ran the read unchecked, bounded by nothing but the mode -- and
// the executor holds the client group, so a file declared inside the enrolled
// tree was readable through it.
func TestABrokeredCommandMayNotReadABlockedPath(t *testing.T) {
	check := blocking(pathEntry("/srv/keys/luks.key"))

	rule, refused := check.refuses([]string{"cat", "/srv/keys/luks.key"}, "/home/op/project")

	if !refused {
		t.Fatal("a brokered `cat` of a declared path was allowed, which is the whole " +
			"of what the entry was written to prevent")
	}
	if !strings.Contains(rule.what, "/srv/keys/luks.key") {
		t.Errorf("the refusal names %q, want the entry that matched", rule.what)
	}
}

// The reading only the broker can make. A rule matches the command as written
// and the guard has no working directory to resolve a relative path against, so
// `cd /srv/keys && cat luks.key` walks past it there. The broker is handed the
// cwd with the command, so the file the command would open is knowable.
func TestABlockedPathIsRefusedFromItsOwnDirectory(t *testing.T) {
	check := blocking(pathEntry("/srv/keys/luks.key"))

	if _, refused := check.refuses([]string{"cat", "luks.key"}, "/srv/keys"); !refused {
		t.Error("a relative read from the file's own directory was allowed")
	}
	// And the spelling that is the same file the long way round.
	if _, refused := check.refuses([]string{"cat", "/srv/keys/../keys/luks.key"}, "/tmp"); !refused {
		t.Error("a path reaching the file through .. was allowed")
	}
	// A relative name that is not the blocked file is left alone, or every
	// command in that directory would be refused.
	if _, refused := check.refuses([]string{"cat", "notes.md"}, "/srv/keys"); refused {
		t.Error("an unrelated file in the same directory was refused")
	}
}

// Referring to a declared file is not reading it. A brokered command runs as an
// account of its own and only where an operator asked for it, so managing the
// file it names is ordinary work: none of these puts a byte of it into the
// conversation, and refusing them would take out the converge that rotates the
// key while leaving the disclosure this exists for untouched.
func TestABrokeredCommandMayStillWorkOnABlockedPath(t *testing.T) {
	check := blocking(pathEntry("/srv/keys/luks.key"))

	for _, cmd := range [][]string{
		{"chmod", "0600", "/srv/keys/luks.key"},
		{"chown", "root:root", "/srv/keys/luks.key"},
		{"rm", "/srv/keys/luks.key"},
		{"cryptsetup", "luksOpen", "--key-file", "/srv/keys/luks.key", "/dev/sda2"},
		{"stat", "/srv/keys/luks.key"},
		{"test", "-f", "/srv/keys/luks.key"},
		{"ls", "-l", "/srv/keys/luks.key"},
	} {
		if rule, refused := check.refuses(cmd, "/tmp"); refused {
			t.Errorf("%v was refused by %q: it names the file, it does not read it",
				cmd, rule.what)
		}
	}
}

// The readers are refused whichever way the file reaches the output: a copy to
// be read somewhere unmatched is the same disclosure, which is why the
// vocabulary carries the copiers and the interpreters.
func TestTheReadersAreRefusedWhateverTheyAreCalled(t *testing.T) {
	check := blocking(pathEntry("/srv/keys/luks.key"))

	for _, cmd := range [][]string{
		{"head", "-c", "16", "/srv/keys/luks.key"},
		{"base64", "/srv/keys/luks.key"},
		{"cp", "/srv/keys/luks.key", "/tmp/copy"},
		{"tar", "-cf", "/tmp/x.tar", "/srv/keys/luks.key"},
		{"python3", "-c", "print(open('/srv/keys/luks.key').read())"},
		{"sh", "-c", "cat /srv/keys/luks.key"},
		{"sh", "-c", "while read l; do echo $l; done < /srv/keys/luks.key"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); !refused {
			t.Errorf("%v was allowed", cmd)
		}
	}
}

// A name is matched against the path the command names rather than against this
// host's filesystem, which is how it reaches a file the host does not have at
// that path.
func TestABlockedNameIsRefusedWhereverItTurnsUp(t *testing.T) {
	check := blocking(nameEntry(".env*"))

	for _, cmd := range [][]string{
		{"cat", "/home/op/project/.env.local"},
		{"cat", ".env"},
	} {
		if _, refused := check.refuses(cmd, "/home/op/project"); !refused {
			t.Errorf("%v was allowed by a declared name", cmd)
		}
	}
	// The prefix is a prefix of the name, not of any word: faramir.env holds
	// refs and is meant to be read.
	if _, refused := check.refuses([]string{"cat", "/home/op/faramir.env"}, "/tmp"); refused {
		t.Error("a file the prefix does not name was refused")
	}
}

// A declared command is about what a tool does rather than what it points at,
// and through this route it discloses exactly as much: faramir_run(["op","read",
// …]) prints the credential into the conversation.
func TestADeclaredCommandIsRefusedThroughTheBroker(t *testing.T) {
	check := blocking(config.BlockedPath{Command: "op read"})

	for _, cmd := range [][]string{
		{"op", "read", "op://vault/db/password"},
		{"/usr/bin/op", "read", "op://vault/db/password"},
		{"sh", "-c", "op read op://vault/db/password"},
		{"sudo", "op", "read", "op://vault/db/password"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); !refused {
			t.Errorf("%v was allowed", cmd)
		}
	}
	// Matched where a command starts, not wherever the words appear: a search
	// naming the declared command is not running it.
	if _, refused := check.refuses([]string{"grep", "-r", "op read", "playbooks/"}, "/tmp"); refused {
		t.Error("a command merely named inside an argument was refused")
	}
}

// A host that declares nothing refuses nothing. Worth holding: the rules are
// built from an alternation, and an empty one matches the empty string beside
// any reader, which would refuse every command on every host that never ran
// `faramir block add`.
func TestNoEntriesRefusesNothing(t *testing.T) {
	check := blocking()
	for _, cmd := range [][]string{
		{"cat", "/etc/hostname"}, {"ls"}, {"ansible-playbook", "site.yml"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); refused {
			t.Errorf("%v was refused on a host that declares nothing", cmd)
		}
	}
}

// The refusal reaches a model rather than the operator, so it says which entry
// matched, why no other answer was available, and whose the remedy is. Naming
// the one entry is safe where naming the set would not be: `faramir block ls`
// is the operator's command for the whole list.
func TestTheRefusalNamesTheEntryAndTheRemedy(t *testing.T) {
	rule, _ := blocking(pathEntry("/srv/keys/luks.key")).
		refuses([]string{"cat", "/srv/keys/luks.key"}, "/tmp")
	said := declaredRefusal(rule)
	for _, want := range []string{
		"the path /srv/keys/luks.key", // which entry, and which form it took
		"never reads",                 // why the output cannot be covered instead
		"faramir block rm",            // and whose the remedy is
		"Changing it where it stands is not refused",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, said)
		}
	}
	// A link's refusal points at the link's own remedy, and names the ref: what
	// a caller is meant to do with a linked credential is ask for it by name.
	linkRule, _ := linking(config.Link{Ref: "gh/token", Path: "/home/op/.config/gh/hosts.yml", Type: "yaml", Key: "k"}).
		refuses([]string{"cat", "/home/op/.config/gh/hosts.yml"}, "/tmp")
	linkSaid := declaredRefusal(linkRule)
	for _, want := range []string{"gh/token", "/home/op/.config/gh/hosts.yml", "faramir link rm"} {
		if !strings.Contains(linkSaid, want) {
			t.Errorf("a link's refusal does not say %q:\n%s", want, linkSaid)
		}
	}
}

// A link and a block are held to the same rule through the broker. A linked
// file's own ref comes back tokenised wherever it appears, but a file holds
// more than the key a link selects: the rest of it is in no redactor, and the
// mode that keeps the executor out is checked at install time rather than at
// the moment the command runs.
func TestALinkedFileIsRefusedTheSameWay(t *testing.T) {
	check := linking(config.Link{
		Ref: "gh/token", Path: "/home/op/.config/gh/hosts.yml", Type: "yaml",
		Key: "github.com/oauth_token"})

	if _, refused := check.refuses([]string{"cat", "/home/op/.config/gh/hosts.yml"}, "/tmp"); !refused {
		t.Error("a brokered read of a linked file was allowed")
	}
	if _, refused := check.refuses([]string{"chmod", "0600", "/home/op/.config/gh/hosts.yml"}, "/tmp"); refused {
		t.Error("changing a linked file where it stands was refused")
	}
}

// The line is not the read/write one. A command that leaves the contents under
// a name no rule was written for discloses the file one step later, and the
// agent reads the copy with its own tools: nothing declares /tmp/x.
func TestMovingADeclaredFileIsRefusedLikeReadingIt(t *testing.T) {
	check := blocking(pathEntry("/srv/keys/luks.key"))

	for _, cmd := range [][]string{
		{"mv", "/srv/keys/luks.key", "/tmp/x"},
		{"ln", "-s", "/srv/keys/luks.key", "/tmp/x"},
		{"sed", "-n", "p", "/srv/keys/luks.key"},
		{"gzip", "/srv/keys/luks.key"},
		{"xz", "/srv/keys/luks.key"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); !refused {
			t.Errorf("%v was allowed: the file ends up readable under a name no rule "+
				"names, which is the same disclosure one step later", cmd)
		}
	}
}

// Through the op, which is what a caller meets: the code is its own, the
// refusal is terminal, and the record is written like every other one.
func TestARunNamingABlockedPathIsRefusedWithItsOwnCode(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	s.declared = blocking(pathEntry("/srv/keys/luks.key"))
	peer := &sockutil.Peer{PID: 4242, UID: 1000, GID: 1000}

	response := handle(s, map[string]any{
		"op": "run", "cmd": []any{"cat", "/srv/keys/luks.key"}, "cwd": "/tmp",
	}, peer)

	failure, ok := response["error"].(map[string]string)
	if !ok {
		t.Fatalf("the command was not refused: %v", response)
	}
	if failure["code"] != codeBlocked {
		t.Errorf("code = %q, want %q", failure["code"], codeBlocked)
	}
	logID, _ := response["log_id"].(string)
	if logID == "" {
		t.Fatal("the refusal carried no log_id, so nothing can be looked up")
	}
	found := false
	for _, record := range records(t, s) {
		if record["log_id"] == logID {
			found = true
			if record["refused"] != codeBlocked {
				t.Errorf("record says refused=%v, want %q", record["refused"], codeBlocked)
			}
		}
	}
	if !found {
		t.Errorf("no audit record for %s", logID)
	}
}

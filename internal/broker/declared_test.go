package broker

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/sockutil"
)

// blocking is a check over the entries a host declares, with no home to expand
// a "~" against: the spellings that need one are the agent's own shell's, and
// this is the brokered route.
func blocking(entries ...config.BlockedPath) declaredCheck {
	return newDeclaredCheck(denyrules.For("", nil, "", config.SecretConfig{Blocked: entries}))
}

// linking is the same for a [[secret.link]] entry, which is held to the same
// rule: the file holds more than the one ref a link selects, and the rest of it
// is in no redactor.
func linking(links ...config.Link) declaredCheck {
	return newDeclaredCheck(denyrules.For("", nil, "", config.SecretConfig{Links: links}))
}

func pathEntry(path string) config.BlockedPath { return config.BlockedPath{Path: path} }

// The hole this closes. A blocked path is refused to the agent's file tools and
// to its shell, and neither rule reaches the broker: the guard is a hook over
// the agent's own tools, and a command on the far side of it is not one. So
// the one route the
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
	if !strings.Contains(declaredSubject(rule), "/srv/keys/luks.key") {
		t.Errorf("the refusal names %q, want the entry that matched", declaredSubject(rule))
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
// account of its own, so managing the
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
				cmd, declaredSubject(rule))
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

// A declared directory covers everything under it, which is what reaches a key
// under a name no list of key names would carry.
func TestADeclaredDirectoryCoversWhatIsUnderIt(t *testing.T) {
	check := blocking(pathEntry("/home/op/.ssh"))

	for _, cmd := range [][]string{
		{"cat", "/home/op/.ssh/id_rsa"},
		// The key name no enumeration would have carried, which is what a
		// directory entry covers and a list of file names does not.
		{"cat", "/home/op/.ssh/identity"},
		{"cat", "/home/op/.ssh"},
	} {
		if _, refused := check.refuses(cmd, "/home/op/project"); !refused {
			t.Errorf("%v was allowed by a declared directory", cmd)
		}
	}
	// A neighbour whose name merely starts the same way is not under it.
	if _, refused := check.refuses([]string{"cat", "/home/op/.ssh-notes"}, "/tmp"); refused {
		t.Error("a sibling of the declared directory was refused")
	}
}

// A declared command is about what a tool does rather than what it points at,
// and through this route it discloses exactly as much: faramir run(["op","read",
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
		"A command outside it is not refused",
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

// The line is what the command puts in the output, not what it does to the file.
//
// This route runs what the operator asked for, as an account of their own, so it
// does not defend against a name being walked out from under a rule: moving a
// declared file, linking it or compressing it is the operator managing their own
// file, and each is allowed. `--strict` is how an entry says otherwise.
//
// What stays refused is anything that prints the contents, whatever it is
// called: `sed -n p` is a read with another name.
func TestTheBrokeredRouteRefusesWhatPrintsAndAllowsWhatMoves(t *testing.T) {
	check := blocking(pathEntry("/srv/keys/luks.key"))

	for _, cmd := range [][]string{
		{"sed", "-n", "p", "/srv/keys/luks.key"},
		{"cat", "/srv/keys/luks.key"},
		{"base64", "/srv/keys/luks.key"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); !refused {
			t.Errorf("%v was allowed, and it prints the file", cmd)
		}
	}
	for _, cmd := range [][]string{
		{"mv", "/srv/keys/luks.key", "/tmp/x"},
		{"ln", "-s", "/srv/keys/luks.key", "/tmp/x"},
		{"gzip", "/srv/keys/luks.key"},
		{"xz", "/srv/keys/luks.key"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); refused {
			t.Errorf("%v was refused, and it is the operator managing their own file", cmd)
		}
	}
	// And --strict is what refuses those too.
	strict := blocking(config.BlockedPath{Path: "/srv/keys/luks.key", Strict: true})
	if _, refused := strict.refuses([]string{"mv", "/srv/keys/luks.key", "/tmp/x"}, "/tmp"); !refused {
		t.Error("a strict entry allowed a brokered mv, which is what the flag is for")
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

// The stricter reading, asked for per entry. The default has to be the one that
// leaves a host working -- a keyfile nothing may chmod is a keyfile nothing may
// rotate -- but that trade does not apply to the directory the agent has no
// business in at all, where `ls` is as unwelcome as `cat`.
func TestStrictRefusesEveryCommandNamingTheEntry(t *testing.T) {
	check := blocking(config.BlockedPath{Path: "/home/op/.private", Strict: true})

	for _, cmd := range [][]string{
		{"ls", "-l", "/home/op/.private"},
		{"stat", "/home/op/.private/notes"},
		{"chmod", "0700", "/home/op/.private"},
		{"test", "-d", "/home/op/.private"},
		{"cat", "/home/op/.private/key"},
		{"sh", "-c", "cd /home/op/.private && make"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); !refused {
			t.Errorf("%v was allowed by a --strict entry", cmd)
		}
	}
	// A sibling that merely starts the same way is not the same path: the
	// subject is bounded, so an entry does not reach past its own name.
	if _, refused := check.refuses([]string{"ls", "/home/op/.private-notes.md"}, "/tmp"); refused {
		t.Error("an entry reached a sibling that only starts the same way")
	}
}

// And it stays per entry. Two declared files, one strict and one not, are two
// readings on the same host: the flag is not a mode the install is in.
func TestStrictIsPerEntry(t *testing.T) {
	check := blocking(
		config.BlockedPath{Path: "/home/op/.private", Strict: true},
		config.BlockedPath{Path: "/srv/keys/luks.key"},
	)

	if _, refused := check.refuses([]string{"chmod", "0700", "/home/op/.private"}, "/tmp"); !refused {
		t.Error("the strict entry allowed a chmod")
	}
	if _, refused := check.refuses([]string{"chmod", "0600", "/srv/keys/luks.key"}, "/tmp"); refused {
		t.Error("the ordinary entry refused a chmod, which is how a key is rotated")
	}
}

// A link takes the same flag, for the file whose own tool is the only thing
// that should ever touch it.
func TestALinkTakesStrictToo(t *testing.T) {
	check := linking(config.Link{
		Ref: "gh/token", Path: "/home/op/.config/gh/hosts.yml", Type: "yaml",
		Key: "github.com/oauth_token", Strict: true})

	if _, refused := check.refuses([]string{"ls", "-l", "/home/op/.config/gh/hosts.yml"}, "/tmp"); !refused {
		t.Error("a strict link allowed a listing of its file")
	}
}

// The refusal has to carry why, or its reader reaches for a way round it: a
// command refused for naming a path it never read reads as a fault otherwise.
func TestTheStricterRefusalSaysItIsStricter(t *testing.T) {
	rule, _ := blocking(config.BlockedPath{Path: "/home/op/.private", Strict: true}).
		refuses([]string{"ls", "/home/op/.private"}, "/tmp")

	if !strings.Contains(declaredRefusal(rule), "no command may name at all") {
		t.Errorf("the refusal does not say the entry is the stricter kind:\n%s",
			declaredRefusal(rule))
	}
}

// An argv word is literal. A ";", a "|" or an "&" inside one reaches the
// program as an argument, and reading it as a separator splits the command in
// two: the path lands in a piece with no reader in front of it and the rule
// stops matching. `cat ';' <path>` prints the file with the separator as a
// failed operand, so this is a bypass and not only an accounting error, and
// `sort -t'|'` is an ordinary command that would miss by accident.
func TestASeparatorInsideAnArgumentDoesNotSplitTheCommand(t *testing.T) {
	check := blocking(pathEntry("/srv/keys/luks.key"))
	for _, cmd := range [][]string{
		{"/bin/cat", ";", "/srv/keys/luks.key"},
		{"/bin/cat", "&", "/srv/keys/luks.key"},
		{"/bin/cat", "|", "/srv/keys/luks.key"},
		{"sort", "-t|", "-k2", "/srv/keys/luks.key"},
		{"cp", "--suffix=;", "/srv/keys/luks.key", "/tmp/copy"},
	} {
		if _, refused := check.refuses(cmd, "/home/op/project"); !refused {
			t.Errorf("%v was allowed: a separator inside an argument split the command", cmd)
		}
	}
}

// And the other side of that line, which is why an argv is not simply matched
// whole: the string a shell is handed is a command list, and a reader in the
// first command must not reach a path named in the second. Rotating a declared
// key beside an unrelated read is the case that costs, and the entry leaves
// changing the file where it stands alone.
func TestAShellStringIsStillReadOneCommandAtATime(t *testing.T) {
	check := blocking(pathEntry("/srv/keys/luks.key"))
	if _, refused := check.refuses(
		[]string{"sh", "-c", "cat notes.md; chmod 640 /srv/keys/luks.key"}, "/home/op"); refused {
		t.Error("a chmod of a declared file was refused for a read of another file " +
			"on the same line, which is the converge that rotates the key")
	}
	// The handoff one word later, which is how a model writes it as often as not.
	for _, cmd := range [][]string{
		{"sudo", "sh", "-c", "cat /srv/keys/luks.key"},
		{"env", "FOO=1", "/bin/bash", "-c", "cat /srv/keys/luks.key"},
	} {
		if _, refused := check.refuses(cmd, "/home/op"); !refused {
			t.Errorf("%v was allowed: the shell's own string went unread", cmd)
		}
	}
}

// The refusal reaches a model, so the sentence saying what the entry leaves
// alone has to be true of the entry that matched. An strict entry leaves
// nothing alone: telling its reader that changing the file in place is fine
// sends it back for the same `ls` or `chmod` and a second refusal.
func TestAnStrictRefusalDoesNotPromiseTheFileCanBeChanged(t *testing.T) {
	strict := config.BlockedPath{Path: "/home/op/.private", Strict: true}
	rule, refused := blocking(strict).refuses([]string{"ls", "-l", "/home/op/.private"}, "/home/op")
	if !refused {
		t.Fatal("a listing of a strict path was allowed")
	}
	said := declaredRefusal(rule)
	if strings.Contains(said, "A command outside it is not refused") {
		t.Errorf("the refusal for a strict entry says the file can still be "+
			"changed, having just refused a command that would:\n%s", said)
	}
	if !strings.Contains(said, "no command may name it") {
		t.Errorf("the refusal does not say what the entry actually covers:\n%s", said)
	}
	// The looser entry keeps the sentence, that being what it promises.
	loose, _ := blocking(pathEntry("/srv/keys/luks.key")).
		refuses([]string{"cat", "/srv/keys/luks.key"}, "/tmp")
	if !strings.Contains(declaredRefusal(loose), "A command outside it is not refused") {
		t.Error("an ordinary entry stopped naming what it leaves alone")
	}
}

// occupying is a check over the directories this install occupies, which no
// entry declares. The guard refuses an agent naming one; this asserts the other
// route, where a mode is no answer: a brokered command runs as an account of its
// own, and as root wherever an escalation was approved.
func occupying(dirs ...string) declaredCheck {
	return newDeclaredCheck(denyrules.For("", dirs, "", config.SecretConfig{}))
}

// A brokered command may not name one, whatever it would do with it, which is
// the shape a --strict entry gets. Not the looser reading a declared path gets:
// that exists so a brokered command can still manage a credential file, and
// nothing brokered has an install to manage.
func TestABrokeredCommandMayNotNameFaramirsOwnDirectories(t *testing.T) {
	check := occupying("/etc/faramir", "/usr/local/libexec/faramir")

	for _, cmd := range [][]string{
		{"cat", "/etc/faramir/age.key"},
		{"sudo", "cat", "/etc/faramir/age.key"},
		{"chmod", "644", "/etc/faramir/age.key"},
		{"cp", "-a", "/etc/faramir", "/tmp/x"},
		{"ls", "-l", "/etc/faramir"},
		{"tee", "/usr/local/libexec/faramir/wrap.sh"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); !refused {
			t.Errorf("%v was allowed, and it names one of faramir's own directories", cmd)
		}
	}

	// The rules match the text of a command, so what a command does once it is
	// running is not this. A converge that sets the install up goes through.
	for _, cmd := range [][]string{
		{"ansible-playbook", "site.yml"},
		{"cat", "/etc/faramir-notes.md"},
		{"cat", "/srv/keys/luks.key"},
	} {
		if _, refused := check.refuses(cmd, "/tmp"); refused {
			t.Errorf("%v was refused, and it names none of faramir's own directories", cmd)
		}
	}
}

// The refusal offers no removal command, there being no entry to remove: one
// naming `faramir block rm` sends the operator to a command that would find
// nothing.
func TestTheOwnDirectoryRefusalOffersNoRemoval(t *testing.T) {
	rule, refused := occupying("/etc/faramir").refuses(
		[]string{"cat", "/etc/faramir/age.key"}, "/tmp")
	if !refused {
		t.Fatal("a read of faramir's own directory was allowed")
	}
	message := declaredRefusal(rule)
	if strings.Contains(message, "block rm") || strings.Contains(message, "link rm") {
		t.Errorf("the refusal names a removal command for a rule no entry stands "+
			"behind: %s", message)
	}
	if !strings.Contains(message, "no entry to remove") {
		t.Errorf("the refusal does not say why there is nothing to take back: %s", message)
	}
}

// A command entry gets the sentence written for a command. Told instead what a
// reader may still do to a file, somebody who ran `op read` is being answered
// about a path they never typed.
func TestACommandRefusalIsNotWrittenAboutAPath(t *testing.T) {
	rule, refused := newDeclaredCheck(denyrules.For("", nil, "", config.SecretConfig{
		Blocked: []config.BlockedPath{{Command: "op read"}},
	})).refuses([]string{"op", "read", "op://vault/item/field"}, "/tmp")
	if !refused {
		t.Fatal("a blocked command ran, so this asserts nothing")
	}

	said := declaredRefusal(rule)
	// The removal as well as the refusal, and the form it goes out under: an
	// entry comes back out under the flag it went in under, so the path spelling
	// would name nothing that lifts this one.
	for _, want := range []string{"the blocks", "no brokered command may run it", "--command"} {
		if !strings.Contains(said, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, said)
		}
	}
	// The path tail, which is about a file and has none to be about here.
	for _, unwanted := range []string{"`cp`, `tee` and `sed`", "whatever it does to the file"} {
		if strings.Contains(said, unwanted) {
			t.Errorf("the refusal for a command carries %q, which is a path's sentence:\n%s",
				unwanted, said)
		}
	}
}

// Which list the entry is in, rather than that it was declared: "declared" names
// no command the reader can run, and the two lists have two different removals.
func TestARefusalNamesTheListTheEntryIsIn(t *testing.T) {
	blocked, _ := blocking(pathEntry("/srv/keys/luks.key")).
		refuses([]string{"cat", "/srv/keys/luks.key"}, "/tmp")
	if said := declaredRefusal(blocked); !strings.Contains(said, "the blocks on this host") {
		t.Errorf("a blocked path's refusal does not name the blocks:\n%s", said)
	}

	linked, _ := linking(config.Link{
		Ref: "gh/token", Path: "/home/op/.config/gh/hosts.yml", Type: "yaml",
		Key: "github.com/oauth_token"}).
		refuses([]string{"cat", "/home/op/.config/gh/hosts.yml"}, "/tmp")
	if said := declaredRefusal(linked); !strings.Contains(said, "the links on this host") {
		t.Errorf("a linked file's refusal does not name the links:\n%s", said)
	}

	// A strict entry says so inside its own subject, ending on a comma that the
	// clause after it supplies as well.
	strict, _ := blocking(config.BlockedPath{Path: "/srv/keys/luks.key", Strict: true}).
		refuses([]string{"ls", "/srv/keys/luks.key"}, "/tmp")
	if said := declaredRefusal(strict); strings.Contains(said, ",,") {
		t.Errorf("the refusal punctuates the subject twice:\n%s", said)
	}
}

// The broker's own key, which --ssh-key may put outside every directory the
// layout renders. The guard refuses it either way; this is the route where a
// mode is no answer, an approved escalation running as root, and where the rule
// was missing while the guard's rendered file carried one.
func TestARelocatedBrokerKeyIsRefusedByTheBroker(t *testing.T) {
	const key = "/srv/keys/broker_ed25519"
	check := newDeclaredCheck(denyrules.For(
		"/home/op", []string{"/etc/faramir"}, key, config.SecretConfig{}))
	for _, command := range [][]string{
		{"cat", key},
		{"sudo", "cat", key},
		{"ls", "-l", key},
	} {
		if _, refused := check.refuses(command, "/tmp"); !refused {
			t.Errorf("%v is allowed, and it names the key the broker lends", command)
		}
	}
	// The rule is the key and not the directory holding it: a sibling under the
	// same directory is nothing faramir installed.
	if _, refused := check.refuses([]string{"cat", "/srv/keys/other.pem"}, "/tmp"); refused {
		t.Error("a file beside the key is refused, so the rule is about the " +
			"directory rather than about the key")
	}
	// And no key configured leaves nothing behind that matches everything.
	none := newDeclaredCheck(denyrules.For(
		"/home/op", []string{"/etc/faramir"}, "", config.SecretConfig{}))
	if _, refused := none.refuses([]string{"cat", "/srv/keys/broker_ed25519"}, "/tmp"); refused {
		t.Error("a host with no [ssh] key refuses a path no entry names")
	}
}

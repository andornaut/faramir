package broker

import (
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// What --strict changes, asserted rather than described. The guard refuses a
// declared path named at all either way, so this route is the only one the flag
// still reaches.
func TestStrictNarrowsTheBrokeredRouteAndNothingElse(t *testing.T) {
	const path = "/srv/keys/luks.key"

	for _, tc := range []struct {
		argv     []string
		ordinary bool // refused without --strict?
		why      string
	}{
		// Refused either way: the contents go somewhere the caller can read.
		{[]string{"cat", path}, true, "a read"},
		{[]string{"sed", "-n", "p", path}, true, "sed prints a file as surely as cat does"},

		// Allowed without --strict. The file changes, or moves, or is used, and
		// none of that puts its contents in the output. A keyfile nothing may
		// chmod is one nothing may rotate, and the account on this route is the
		// operator's own doing what they asked for: it is not the thing being
		// defended against, so a name walked out from under a rule is not this
		// route's problem.
		{[]string{"mv", path, "/tmp/x"}, false, "moving the operator's own file"},
		{[]string{"ln", "-s", path, "/tmp/x"}, false, "and linking it"},
		{[]string{"chmod", "0600", path}, false, "a mode change"},
		{[]string{"chown", "root:root", path}, false, "an ownership change"},
		{[]string{"rm", path}, false, "removal discloses nothing"},
		{[]string{"truncate", "-s", "0", path}, false, "nor does truncation"},
		{[]string{"cryptsetup", "luksOpen", "--key-file", path, "/dev/sda2"}, false,
			"and using the credential is what the brokered route is for"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			ordinary := blocking(pathEntry(path))
			if _, refused := ordinary.refuses(tc.argv, "/home/op"); refused != tc.ordinary {
				t.Errorf("without --strict: refused = %v, want %v", refused, tc.ordinary)
			}
			// With --strict, naming it is enough, so every one of these is
			// refused.
			strict := blocking(config.BlockedPath{Path: path, Strict: true})
			if _, refused := strict.refuses(tc.argv, "/home/op"); !refused {
				t.Errorf("with --strict: allowed, and it names the declared path")
			}
		})
	}
}

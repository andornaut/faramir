package secretlink

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The listing an operator gets when their selector named nothing. Section
// headers become the prefix the selector carries, comments and headers are not
// entries, and a line with no "=" is not one either.
func TestTheKeysAnINIFileOffersAreNamedTheWayASelectorIs(t *testing.T) {
	// The shape .npmrc and most tool dotfiles take, with a section and without.
	data := []byte("; a comment\n" +
		"//registry.npmjs.org/:_authToken = npm_example\n" +
		"# another comment\n" +
		"[distributionManagement]\n" +
		"password = deployer\n" +
		"not an entry\n")

	got := Keys(kindINI, data)

	want := []string{"//registry.npmjs.org/:_authToken", "distributionManagement/password"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Keys = %v, want %v", got, want)
	}
}

// Names only, whatever the kind. This listing is the one thing `faramir
// read-link` prints about a file it could not select from, and it is printed to
// a terminal the agent reads: a value reaching it would be the leak the whole
// command exists to avoid.
func TestAListingOffersNamesAndNeverValues(t *testing.T) {
	const value = "gho_the-actual-credential"
	for _, tc := range []struct{ kind, body string }{
		{kindJSON, `{"github.com": {"oauth_token": "` + value + `"}}`},
		{KindYAML, "github.com:\n    oauth_token: " + value + "\n"},
		{kindTOML, "[\"github.com\"]\noauth_token = \"" + value + "\"\n"},
		{kindINI, "[github.com]\noauth_token = " + value + "\n"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			keys := Keys(tc.kind, []byte(tc.body))
			if len(keys) == 0 {
				t.Fatal("no keys offered, so this asserts nothing")
			}
			for _, key := range keys {
				if strings.Contains(key, value) {
					t.Errorf("the listing carries the value: %q", key)
				}
			}
		})
	}
}

// The whole-file kinds select nothing, so there is nothing to offer: a listing
// of keys against a file read whole would name selectors that do not apply.
func TestTheWholeFileKindsOfferNoKeys(t *testing.T) {
	for _, kind := range []string{KindText, kindBase64, "not-a-kind"} {
		if keys := Keys(kind, []byte("a-secret-value\n")); len(keys) != 0 {
			t.Errorf("%s offers %v, want nothing", kind, keys)
		}
	}
}

// A file that does not parse offers nothing rather than a partial listing: half
// a file's keys read as the whole of them, and an operator told their selector
// is not among them would be looking for a typo they did not make.
func TestAFileThatDoesNotParseOffersNothing(t *testing.T) {
	for _, kind := range []string{kindJSON, KindYAML, kindTOML} {
		if keys := Keys(kind, []byte("{{{ not this kind at all")); len(keys) != 0 {
			t.Errorf("%s offers %v for a file it cannot read, want nothing", kind, keys)
		}
	}
}

// keysIn reads through the same bound Read uses, so a link pointed at something
// enormous is refused for its size rather than slurped to enumerate it.
func TestKeysInReportsAFileItCannotRead(t *testing.T) {
	if _, err := keysIn(filepath.Join(t.TempDir(), "gone.json"), kindJSON); err == nil {
		t.Error("a missing file was not reported")
	}

	path := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(path, make([]byte, maxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := keysIn(path, kindJSON); err == nil {
		t.Error("an oversize file was enumerated rather than refused")
	}
}

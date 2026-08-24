package secretref

import "testing"

// A ref starts with an alphanumeric, which refuses a leading ".." or an empty
// first segment. A ".." in the middle is accepted: a ref is a key into the
// flattened decrypted tree, never a path, so it comes back as unknown_secret.
func TestParseAcceptsARefAndRefusesALiteral(t *testing.T) {
	for _, tc := range []struct {
		uri  string
		want string // "" means the ref must be refused
		why  string
	}{
		{"faramir://home/router/admin", "home/router/admin", "the ordinary form"},
		{"faramir://a/../b", "a/../b", "a mid-ref .. is a key that will not resolve, not a path"},
		{"hunter2", "", "a literal value where a ref belongs must be refused, not injected"},
		{"", "", "nothing at all"},
		{"http://example.com/x", "", "another scheme is not this one"},
		{"secret://home/router/admin", "", "the scheme this replaced must not still resolve"},
		{"faramir://../../etc/passwd", "", "a leading .. is refused by the first-character rule"},
		{"faramir:///etc/passwd", "", "an empty first segment, likewise"},
		{"faramir://.hidden", "", "a leading dot"},
		{"faramir://-flag", "", "a leading dash"},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			ref, err := Parse(tc.uri)
			if tc.want == "" {
				if err == nil {
					t.Errorf("accepted %q: %s", tc.uri, tc.why)
				}
				return
			}
			if err != nil {
				t.Fatalf("%v: %s", err, tc.why)
			}
			if ref != tc.want {
				t.Errorf("ref = %q, want %q", ref, tc.want)
			}
		})
	}
}

// `faramir refs` prints faramir://api/token and a [[secret.link]] entry stores
// api/token, so a ref pasted from the one into the other arrives with the
// scheme still on it. Refused, the operator reads that the name they can see
// on their screen is not one a reference can carry.
func TestABareRefIsTheNameWithOrWithoutTheScheme(t *testing.T) {
	for _, tc := range []struct{ given, want string }{
		{"faramir://api/token", "api/token"},
		{"api/token", "api/token"},
		{"  faramir://api/token  ", "api/token"},
		{"appenv", "appenv"},
		// Only the leading one: the scheme is not part of a name, so a second
		// spelling of it inside the ref is not a prefix to take off.
		{"faramir://faramir://a", "faramir://a"},
		{"", ""},
	} {
		if got := Bare(tc.given); got != tc.want {
			t.Errorf("Bare(%q) = %q, want %q", tc.given, got, tc.want)
		}
	}
	// And what comes back is a name Valid accepts, which is the point.
	if !Valid(Bare("faramir://api/token")) {
		t.Error("the bare form of a printed ref is not a valid ref")
	}
}

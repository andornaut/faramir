package secretref

import "testing"

// A ref starts with an alphanumeric, which refuses a leading ".." or an empty
// first segment.  A ".." in the middle is accepted: a ref is a key into the
// flattened decrypted tree, never a path, so it comes back as unknown_secret.
func TestParse(t *testing.T) {
	for _, tc := range []struct {
		uri  string
		want string // "" means the ref must be refused
		why  string
	}{
		{"secret://home/router/admin", "home/router/admin", "the ordinary form"},
		{"secret://a/../b", "a/../b", "a mid-ref .. is a key that will not resolve, not a path"},
		{"hunter2", "", "a literal value where a ref belongs must be refused, not injected"},
		{"", "", "nothing at all"},
		{"http://example.com/x", "", "another scheme is not this one"},
		{"secret://../../etc/passwd", "", "a leading .. is refused by the first-character rule"},
		{"secret:///etc/passwd", "", "an empty first segment, likewise"},
		{"secret://.hidden", "", "a leading dot"},
		{"secret://-flag", "", "a leading dash"},
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

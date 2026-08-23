package secretref

import "testing"

// Parse is what turns an agent's "faramir://a/b" into a ref the store is asked
// for, so anything it accepts has to be a ref Valid agrees with: the two are
// read as one gate.
func FuzzWhatParseAcceptsIsValid(f *testing.F) {
	f.Add("faramir://a/b")
	f.Add("faramir://")
	f.Add("faramir://../../etc/passwd")
	f.Add("FARAMIR://A/B")
	f.Add("hunter2")

	f.Fuzz(func(t *testing.T, uri string) {
		ref, err := Parse(uri)
		if err != nil {
			if ref != "" {
				t.Fatalf("a refused uri came back with a ref: %q", ref)
			}
			return
		}
		if !Valid(ref) {
			t.Fatalf("Parse accepted %q and produced %q, which Valid refuses", uri, ref)
		}
	})
}

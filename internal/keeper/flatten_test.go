package keeper

import (
	"encoding/json"
	"testing"
)

func TestFlattenSkipsSopsMetadataAndBooleans(t *testing.T) {
	var tree any
	if err := json.Unmarshal([]byte(`{
		"sops": {"mac": "deadbeef"},
		"sops_backup_token": "keep-me-please",
		"a": {"b": ["x", "y"]},
		"flag": true,
		"nothing": null,
		"n": 42
	}`), &tree); err != nil {
		t.Fatal(err)
	}
	got := Flatten(tree)

	want := map[string]string{
		"sops_backup_token": "keep-me-please",
		"a/b/0":             "x",
		"a/b/1":             "y",
		"n":                 "42",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for _, absent := range []string{"sops/mac", "sops", "flag", "nothing"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s should not be a secret ref", absent)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected refs: %v", got)
	}
}

// A scalar with no JSON shape is dropped rather than rendered with %v: a Go
// rendering is a spelling no tool prints, so it would sit in the redactor
// matching nothing and be injected as text nobody chose. Ints still format,
// YAML parsers producing them where JSON gives float64.
func TestFlattenDropsWhatItCannotSpell(t *testing.T) {
	got := Flatten(map[string]any{
		"count":  int(7),
		"wide":   int64(9),
		"opaque": struct{ X int }{X: 1},
	})
	if got["count"] != "7" || got["wide"] != "9" {
		t.Errorf("integer leaves = %q and %q, want 7 and 9", got["count"], got["wide"])
	}
	if v, ok := got["opaque"]; ok {
		t.Errorf("opaque = %q, want it absent rather than a Go rendering", v)
	}
}

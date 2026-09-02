package sopsrule

// Reading the recipients a file is sealed to.

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The recipients come out of the sops metadata block, which is cleartext. sops
// writes that block in the shape of the file it encrypted, so a managed dotenv
// or ini file spells the same field with "=" and a flattened key. Every shape
// has to be read: an unrecognised one reports "names no age recipient" after the
// editor has exited, which discards the edit.
func TestRecipientsOfReadsEverySopsEncoding(t *testing.T) {
	const one = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsdqf6nl"
	const two = "age1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzsdqf6nl"

	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{"yaml", "sops:\n    age:\n        - recipient: " + one + "\n", []string{one}},
		{"json", `{"sops":{"age":[{"recipient":"` + one + `"}]}}`, []string{one}},
		{"dotenv", "sops_age__list_0__map_recipient=" + one + "\n", []string{one}},
		{"ini", "[sops]\nage__list_0__map_recipient=" + one + "\n", []string{one}},
		{"two recipients in order", "sops:\n    age:\n        - recipient: " + one +
			"\n        - recipient: " + two + "\n", []string{one, two}},
		{"a repeat is reported once", "recipient: " + one + "\nrecipient: " + one + "\n", []string{one}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret.sops.yml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := SealedTo(path)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("SealedTo = %v, want %v", got, tc.want)
			}
		})
	}
}

// A file with no recipient at all is still refused: there is nothing to
// re-encrypt it to.
func TestRecipientsOfRefusesAFileWithNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.sops.yml")
	if err := os.WriteFile(path, []byte("key: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SealedTo(path); err == nil {
		t.Fatal("a file naming no recipient was accepted")
	}
}

func TestSameRecipientsIgnoresOrder(t *testing.T) {
	if !Same([]string{"age1a", "age1b"}, []string{"age1b", "age1a"}) {
		t.Error("the same two keys in a different order read as a change")
	}
	if Same([]string{"age1a"}, []string{"age1a", "age1b"}) {
		t.Error("an added recipient read as no change")
	}
}

package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestVaultRemovalConfirmationUsesInspectedRefs(t *testing.T) {
	target := filepath.Join(t.TempDir(), "fixture.sops.yml")
	if err := os.WriteFile(target, []byte("approved: synthetic-ciphertext-A\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	called := false
	snapshot, err := removeVaultFile(func(path string, refs []string, refsErr error) bool {
		called = true
		if path != target || refsErr != nil || !slices.Equal(refs, []string{"approved"}) {
			t.Fatal("confirmation did not receive inspected refs")
		}
		if err := os.WriteFile(path, []byte("changed: synthetic-ciphertext-B\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		return true
	}, false, target)
	if !called || err == nil || snapshot == nil || !slices.Equal(snapshot.Refs, []string{"approved"}) {
		t.Fatalf("refusal did not preserve original audit refs: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("changed file was removed")
	}
}

func TestVaultRemovalForceSkipsOnlyConfirmation(t *testing.T) {
	for _, force := range []bool{false, true} {
		target := filepath.Join(t.TempDir(), "fixture.sops.yml")
		if err := os.WriteFile(target, []byte("approved: synthetic-ciphertext-A\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		called := false
		snapshot, err := removeVaultFile(func(path string, refs []string, refsErr error) bool {
			called = true
			return false
		}, force, target)
		if snapshot == nil || !slices.Equal(snapshot.Refs, []string{"approved"}) || called == force {
			t.Fatal("force did not preserve the inspection/confirmation contract")
		}
		if force {
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("forced stable removal did not remove the file")
			}
		} else if !errors.Is(err, errRemovalDeclined) {
			t.Fatalf("declined removal: %v", err)
		}
	}
}

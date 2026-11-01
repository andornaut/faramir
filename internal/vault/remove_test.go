package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func removalFixture(t *testing.T) (string, []byte) {
	t.Helper()
	target := filepath.Join(t.TempDir(), "fixture.sops.yml")
	body := []byte("service:\n  token: synthetic-ciphertext-A\nsops:\n  ignored: synthetic-metadata\n")
	if err := os.WriteFile(target, body, 0o640); err != nil {
		t.Fatal(err)
	}
	return target, body
}

func TestManagedRemovalRefusesChangedConfirmationSnapshot(t *testing.T) {
	for _, change := range []string{"content", "replacement", "missing"} {
		t.Run(change, func(t *testing.T) {
			target, original := removalFixture(t)
			snapshot, err := InspectRemoval(target)
			if err != nil || snapshot.RefsErr != nil || !slices.Equal(snapshot.Refs, []string{"service/token"}) {
				t.Fatalf("inspection: %+v, %v", snapshot, err)
			}
			changed := []byte("replacement:\n  token: synthetic-ciphertext-B\n")
			switch change {
			case "content":
				err = os.WriteFile(target, changed, 0o640)
			case "replacement":
				// Identical bytes on a different inode still require confirmation.
				err = WriteBack(target, original)
				changed = original
			case "missing":
				err = os.Remove(target)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := snapshot.Remove(); err == nil {
				t.Fatal("removed a changed confirmation snapshot")
			}
			if !slices.Equal(snapshot.Refs, []string{"service/token"}) {
				t.Fatal("audit refs no longer describe the inspected snapshot")
			}
			body, err := os.ReadFile(target)
			if change == "missing" {
				if !os.IsNotExist(err) {
					t.Fatalf("missing entry was recreated: %v", err)
				}
			} else if err != nil || !bytes.Equal(body, changed) {
				t.Fatalf("changed entry was modified: %v", err)
			}
		})
	}
}

func TestManagedRemovalKeepsMalformedRefsRemovableWithoutValues(t *testing.T) {
	target, _ := removalFixture(t)
	if err := os.WriteFile(target, []byte("token: [synthetic-ciphertext-with-broken-yaml"), 0o640); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectRemoval(target)
	if err != nil || snapshot.RefsErr == nil {
		t.Fatalf("malformed refs inspection: %v", err)
	}
	if strings.Contains(snapshot.RefsErr.Error(), "synthetic-ciphertext") {
		t.Fatal("ref parsing error exposes a value")
	}
	if err := snapshot.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("approved malformed file remains: %v", err)
	}
}

func TestManagedRemovalUnchangedSnapshotDeletesOnlyOnce(t *testing.T) {
	target, _ := removalFixture(t)
	snapshot, err := InspectRemoval(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := createManaged(target, []byte("new: synthetic-ciphertext-B\n")); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Remove(); err == nil {
		t.Fatal("old approval removed a newly added entry")
	}
}

func TestManagedRemovalRefusesUnreadableAndNonRegularEntries(t *testing.T) {
	target, _ := removalFixture(t)
	if err := os.Chmod(target, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRemoval(target); !os.IsPermission(err) {
		t.Fatalf("unreadable entry was inspected: %v", err)
	}
	if _, err := InspectRemoval(filepath.Dir(target)); err == nil {
		t.Fatal("directory was accepted for managed removal")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("refused inspection modified the entry")
	}
}

func TestManagedPublicationAndRemovalWaitForDirectoryLock(t *testing.T) {
	for _, operation := range []string{"add", "write back", "remove"} {
		t.Run(operation, func(t *testing.T) {
			target, original := removalFixture(t)
			snapshot, err := InspectRemoval(target)
			if err != nil {
				t.Fatal(err)
			}
			started := make(chan struct{})
			finished := make(chan error, 1)
			err = withPublicationLock(func() error {
				go func() {
					close(started)
					switch operation {
					case "add":
						finished <- createManaged(target, original)
					case "write back":
						finished <- WriteBack(target, original)
					case "remove":
						finished <- snapshot.Remove()
					}
				}()
				<-started
				select {
				case err := <-finished:
					t.Fatalf("%s completed while another publication held the lock: %v", operation, err)
				case <-time.After(100 * time.Millisecond):
				}
				// The waiting operation must inspect state after this mutation.
				if operation == "remove" {
					return os.WriteFile(target, []byte("changed: synthetic-ciphertext-B\n"), 0o640)
				}
				return os.Remove(target)
			}, target)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-finished:
				if (operation == "add") != (err == nil) {
					t.Fatalf("%s did not inspect the state after acquiring its lock: %v", operation, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("publication lock was not released")
			}
		})
	}
}

func TestManagedPublicationGuardRefusesAStaleEdit(t *testing.T) {
	target, _ := removalFixture(t)
	before, err := digestOf(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteBack(target, []byte("new: synthetic-ciphertext-B\n")); err != nil {
		t.Fatal(err)
	}
	if err := writeBack(before, target, []byte("stale: synthetic-ciphertext-C\n")); err == nil {
		t.Fatal("stale edit replaced a newer publication")
	}
}

package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/hostfs"
)

func TestManagedPublicationDoesNotReplaceExistingEntry(t *testing.T) {
	for _, kind := range []string{"file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "fixture.sops.yml")
			original := []byte("synthetic existing ciphertext")
			stored := target
			if kind == "symlink" {
				stored = filepath.Join(dir, "retained")
			}
			if err := os.WriteFile(stored, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				if err := os.Symlink(stored, target); err != nil {
					t.Fatal(err)
				}
			}
			err := createManaged(target, []byte("synthetic competing ciphertext"))
			if !errors.Is(err, os.ErrExist) {
				t.Fatalf("publication must refuse an existing entry: %v", err)
			}
			if !strings.Contains(err.Error(), target) || !strings.Contains(err.Error(), "nothing was replaced") {
				t.Fatalf("publication refusal omits target/outcome: %v", err)
			}
			body, err := os.ReadFile(stored)
			if err != nil || !bytes.Equal(body, original) {
				t.Fatalf("existing entry changed: %q, %v", body, err)
			}
			if kind == "symlink" {
				info, err := os.Lstat(target)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("existing symlink replaced: %v", err)
				}
			}
			leftovers, err := filepath.Glob(target + ".*")
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("temporary publication files remain: %v, %v", leftovers, err)
			}
		})
	}
}

// Publication links the temp name and then removes it, so a fresh target is
// the directory's only entry and holds the only link to its inode.
func TestManagedPublicationPublishesFreshTargetAsSoleLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fixture.sops.yml")
	data := []byte("synthetic fresh ciphertext")
	if err := createManaged(target, data); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(body, data) {
		t.Fatalf("published content: %q, %v", body, err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(target, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0o777 != 0o640 {
		t.Fatalf("published entry: mode %o, %d links", st.Mode, st.Nlink)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("publication temporary files remain: %v, %v", entries, err)
	}
}

func TestManagedPublicationConcurrentAddsHaveOneWinner(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o2770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "fixture.sops.yml")
	start := make(chan struct{})
	results := make(chan error, 2)
	var writers sync.WaitGroup
	for _, data := range []string{"synthetic ciphertext A", "synthetic ciphertext B"} {
		writers.Go(func() {
			<-start
			results <- createManaged(target, []byte(data))
		})
	}
	close(start)
	writers.Wait()
	close(results)
	winners, refused := 0, 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, os.ErrExist):
			refused++
		default:
			t.Fatalf("unexpected publication error: %v", err)
		}
	}
	if winners != 1 || refused != 1 {
		t.Fatalf("publication outcomes: %d winners, %d refused", winners, refused)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("published mode: %v, %v", info, err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, actualGroup := hostfs.OwnerOf(info)
	_, directoryGroup := hostfs.OwnerOf(dirInfo)
	if actualGroup != directoryGroup {
		t.Fatalf("published group %d differs from directory %d", actualGroup, directoryGroup)
	}
	body, err := os.ReadFile(target)
	if err != nil || (string(body) != "synthetic ciphertext A" && string(body) != "synthetic ciphertext B") {
		t.Fatalf("publication is not one complete candidate: %q, %v", body, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("publication temporary files remain: %v, %v", entries, err)
	}
}

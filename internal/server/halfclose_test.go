package server

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Nothing that talks to the broker socket may half-close its write side. The
// broker reads a run's connection for the whole of the run and takes an EOF
// there as the caller having gone, so a client that shuts down its write half
// after sending has every brokered command killed the moment it starts.
//
// Read off the source rather than asserted through a socket, because the
// failure is one call in one client: the CLI, the MCP server and the plugins
// each dial this socket, and a test that exercised one would pass while
// another was broken. The keeper's client is exempt and named: it speaks to a
// different socket, which watches nothing.
func TestNothingHalfClosesTheBrokerSocket(t *testing.T) {
	const exempt = "internal/keeperclient/keeperclient.go"
	base := filepath.Join("..", "..")
	// Every read goes through the root, so a symlink planted mid-walk cannot
	// point this at a file outside the checkout.
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	var found []string
	err = filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(base, path)
		if relErr != nil || filepath.ToSlash(rel) == exempt {
			return relErr
		}
		file, openErr := root.Open(rel)
		if openErr != nil {
			return openErr
		}
		defer func() { _ = file.Close() }()
		body, readErr := io.ReadAll(file)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(body), "CloseWrite") {
			found = append(found, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Errorf("these half-close a connection: %s\n"+
			"A run's caller has to hold its write side open until it has the "+
			"answer, or the broker reads the half-close as the caller having "+
			"gone and kills the command.", strings.Join(found, ", "))
	}
}

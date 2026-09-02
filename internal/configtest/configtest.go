// Package configtest builds the config entries tests hand to a renderer.
// Imported only from _test.go files.
package configtest

import "github.com/andornaut/faramir/internal/config"

// RefusedAt is the entries a [[secret.block]] would carry for these paths.
func RefusedAt(paths ...string) []config.BlockedPath {
	out := make([]config.BlockedPath, 0, len(paths))
	for _, path := range paths {
		out = append(out, config.BlockedPath{Path: path})
	}
	return out
}

// LinksAt is the entries a [[secret.link]] would carry for these paths.
func LinksAt(paths ...string) []config.Link {
	out := make([]config.Link, 0, len(paths))
	for _, path := range paths {
		out = append(out, config.Link{Ref: "test", Path: path, Type: "text"})
	}
	return out
}

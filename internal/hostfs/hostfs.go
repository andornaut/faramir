// Package hostfs writes the files and directories an install puts on a host,
// each with the mode and ownership it must end up with.
//
// Two things separate it from the os package it is built on:
//
//   - Every call reports whether it changed anything, so a configuration
//     manager need not stat the host before and after, and a dry run computes
//     the same answer while writing nothing.
//   - A path is resolved once. The check and the write are two operations, and
//     a path checked and then written by path is resolved twice; in between,
//     the account the agent runs as can replace a directory it owns with a
//     link. EditedFile pins the target's directory and everything after it goes
//     through that descriptor.
//
// It knows nothing about what is being installed: no layout, no accounts, no
// units. What decides a mode or an owner is the caller's.
package hostfs

// Keep is the uid or gid value that leaves ownership as it is.
const Keep = -1

// FS is the filesystem side of an install. Every method reports whether it
// changed anything, so a configuration manager need not stat the host before
// and after. With dryRun set each computes the same answer and writes
// nothing.
type FS struct{ DryRun bool }

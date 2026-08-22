// Package denyrules holds the command vocabulary the guard's path rules are
// built from, and the shape those rules take.
//
// Its own package because both sides need it and neither may import the other:
// internal/install renders the shipped pattern file from the protected set it
// already holds, and internal/guard builds the same rules at run time for a
// config directory the file did not name. A copy in each would be two lists
// that agree until one of them is edited.
package denyrules

import (
	"regexp"
	"strings"
)

// The command alternations the path rules share. Readers carry interpreters and
// copiers as well as pagers: reading a key with python, or copying it somewhere
// unmatched and reading it there, is the same disclosure. "sed" is a writer
// only; "grep" is neither, so naming a .env file in a search is not refused.
//
// The decryption tools are readers and writers both, and they are here rather
// than as verb rules of their own: `sops -d` on this install's store is a read
// of it, and `sops -d` on somebody else's file is that host's business. Keeping
// them in the vocabulary refuses the first and leaves the second, where a rule
// on the verb refused every use of the tool anywhere.
const (
	ReadCommands = `\b(?-i:cat|less|more|head|tail|bat|xxd|od|strings|base64|base32|` +
		`hexdump|uuencode|rev|tac|awk|cut|nl|dd|jq|yq|python3?|perl|ruby|tee|cp|` +
		`tar|scp|rsync|sops|age|ansible-vault)\b`
	WriteCommands = `\b(?-i:rm|shred|truncate|mv|cp|tee|dd|sed|chmod|chown|chgrp|` +
		`setfacl|ln|sops|age|ansible-vault)\b`
)

// PathEnd is what may follow a path in a command line: whitespace, a quote, a
// separator, or the end of it. A class rather than \b, and shared so the two
// sides bound a path the same way: "\b" holds beside a hyphen, so a rule for
// /opt/faramir would match /opt/faramir-notes.md and refuse a sibling that
// merely starts the same way.
const PathEnd = `[\s"';&|)]|$`

// Dir is a directory as a subject: the directory itself, or anything under it,
// and nothing that merely begins with its name.
func Dir(dir string) string {
	return regexp.QuoteMeta(dir) + `(?:/|` + PathEnd + `)`
}

// HomeSpellings is the ways a command line names a file under a home: the
// absolute path, and the three prefixes a shell expands to it. A path rule is a
// literal, so `cat ~/.private/x` reaches a file that `cat /home/op/.private/x`
// is refused, and the tilde is how a person and a model both write a home path.
//
// Deliberately not the bare relative spelling. `.private/x` names this file
// only from one directory and names somebody else's from anywhere else, and the
// rule cannot tell which: that breadth is what a name entry is for, where it is
// asked for rather than inferred.
//
// The list is what a shell expands, not every string that could reach the same
// file: a command may build a path a way no rule can enumerate, and this is the
// list that catches an accident rather than the boundary.
func HomeSpellings(home, path string) []string {
	rest, under := strings.CutPrefix(path, strings.TrimSuffix(home, "/")+"/")
	if home == "" || home == "/" || !under || rest == "" {
		return []string{regexp.QuoteMeta(path)}
	}
	tail := regexp.QuoteMeta("/" + rest)
	return []string{
		regexp.QuoteMeta(path),
		regexp.QuoteMeta("~") + tail,
		regexp.QuoteMeta("$HOME") + tail,
		regexp.QuoteMeta("${HOME}") + tail,
	}
}

// DirUnder is Dir for a path that may sit under a home, bounded the same way
// and matching each spelling of it.
func DirUnder(home, dir string) string {
	spellings := HomeSpellings(home, dir)
	if len(spellings) == 1 {
		return spellings[0] + `(?:/|` + PathEnd + `)`
	}
	return `(?:` + strings.Join(spellings, `|`) + `)(?:/|` + PathEnd + `)`
}

// For is the three rules that refuse a set of subjects: reading one, writing
// one, and redirecting output over one.
//
// "[^|]*" stops at the first pipe, so a reader on one side of a pipe and a
// protected path on the other is not read as one command reaching it. The
// redirect rule matches the target word alone, so a heredoc mentioning a path
// is not a write to it.
//
// No subjects is no rules rather than a rule matching everything, an empty
// alternation being one that matches the empty string next to any reader.
func For(subjects []string) []string {
	if len(subjects) == 0 {
		return nil
	}
	alternation := `(` + strings.Join(subjects, `|`) + `)`
	return []string{
		ReadCommands + `[^|]*` + alternation,
		WriteCommands + `[^|]*` + alternation,
		`>\s*\S*` + alternation,
	}
}

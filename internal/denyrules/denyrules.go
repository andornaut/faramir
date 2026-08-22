// Package denyrules holds the command vocabulary the guard's path rules are
// built from, and the shape those rules take.
//
// Its own package because both sides need it and neither may import the other:
// internal/install renders the shipped pattern file from the protected set it
// already holds, and internal/guard builds the same rules at run time for a
// config directory the file did not name. A copy in each would be two lists
// that agree until one of them is edited.
package denyrules

import "strings"

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

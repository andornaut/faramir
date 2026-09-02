// Package denyrules holds the command vocabulary the guard's path rules are
// built from, and the shape those rules take.
//
// Its own package because both sides need it and neither may import the other:
// internal/install renders the shipped pattern file from the protected set it
// already holds, and internal/guard builds the same rules at run time for a
// config directory the file did not name. A copy in each would be two lists
// that agree until one of them is edited.
package denyrules

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
// The list is generous because it costs nothing to be: a rule fires only where
// one of these appears together with a path this host protects, so a word here
// refuses nothing an agent does anywhere else. What decided the additions is
// whether the tool prints a file's contents or makes a copy to read elsewhere:
// `sort FILE` and `diff /dev/null FILE` print it as surely as `cat` does, and
// `find DIR -exec` reaches every file under it. A hash is deliberately absent,
// a transform of a value being the exfiltration the design says it cannot cover.
const (
	readCommands = `\b(?-i:` + gnuPrefix + `(?:cat|less|more|head|tail|bat|xxd|od|` +
		`strings|base64|base32|hexdump|uuencode|rev|tac|awk|cut|nl|dd|jq|yq|sed|` +
		`python3?|perl|ruby|tee|cp|tar|scp|rsync|sops|age|ansible-vault|sort|` +
		`uniq|comm|join|paste|column|fold|expand|unexpand|fmt|pr|shuf|split|` +
		`csplit|diff|find|install|cpio|zcat|gunzip|bzcat|xzcat|zstdcat|` +
		`openssl))\b`
	WriteCommands = `\b(?-i:` + gnuPrefix + `(?:rm|shred|truncate|mv|cp|tee|dd|sed|` +
		`chmod|chown|chgrp|setfacl|ln|sops|age|ansible-vault|install|split|` +
		`csplit|cpio|gzip|bzip2|xz|zstd))\b`
)

// gnuPrefix takes the name a tool has where it is not the default one. Ubuntu
// 26.04 ships uutils as `cat` and the GNU build as `gnucat`, and does that for
// 104 programs, 18 of which are in the vocabulary above. A word boundary does
// not fall inside `gnucat`, so every one of those walked past these rules on
// that release: `gnucat /etc/faramir/age.key` reached the EACCES the deny list
// exists to answer instead of.
//
// Optional, so the ordinary names still match, and only this prefix: a rule
// fires only where one of these words meets a path this host protects, so
// taking a name that is not installed refuses nothing an agent does elsewhere.
const gnuPrefix = `(?:gnu)?`

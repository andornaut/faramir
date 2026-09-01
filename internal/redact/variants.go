package redact

// The expanded value set: stage 2 of the pipeline documented on Package
// redact. One value has many spellings on the way out of a program, and each
// is searched for.

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// base64Variants returns the base64 encodings of value: standard and URL-safe,
// padded and not.
func base64Variants(value string) map[string]bool {
	raw := []byte(value)
	out := map[string]bool{}
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
	} {
		out[enc] = true
		out[strings.TrimRight(enc, "=")] = true
	}
	return out
}

// base32Variants returns the RFC 4648 base32 encodings of value, padded and
// not. TOTP seeds and some token formats are base32, and the unpadded form is
// what `otpauth://` URIs carry.
func base32Variants(value string) map[string]bool {
	enc := base32.StdEncoding.EncodeToString([]byte(value))
	return map[string]bool{
		enc:                         true,
		strings.TrimRight(enc, "="): true,
	}
}

// There is deliberately no HTML/XML entity variant. Every other encoding here
// has one spelling or a closed set of them, which is what makes enumerating it
// possible; entity escaping has neither, each character having a named, a
// decimal and a hexadecimal form, and "&#112;" for a plain "p" being as valid
// as leaving it alone. A list of renderings would cover whichever producer it
// was written against and read as coverage of the rest.

// The characters a percent-encoder leaves alone, beyond the unreserved set.
// Which one a producer uses is the whole difference between its output and
// another's, so each is named for the function that has it.
const (
	// safeQuote is Python's urllib.parse.quote(value, safe=""): nothing beyond
	// the unreserved set.
	safeQuote = ""
	// safeComponent is JavaScript's encodeURIComponent.
	safeComponent = "!*'()"
	// safeURI is JavaScript's encodeURI, which is meant to leave a whole URL
	// usable and so keeps the reserved delimiters too.
	safeURI = "!*'();,/?:@&=+$#"
)

// percentEncode renders value the way a percent-encoder would, with safe naming
// the characters left alone beyond the unreserved ASCII letters, digits and
// "_.-~". plus writes a space as "+", which HTML form encoding does. lower emits
// the hex digits in lower case: the RFC prefers upper and most encoders write
// it, but enough write "%3c" that both spellings are worth carrying.
func percentEncode(value, safe string, plus, lower bool) string {
	format := "%%%02X"
	if lower {
		format = "%%%02x"
	}
	var b strings.Builder
	for _, c := range []byte(value) {
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' || c == '~',
			strings.IndexByte(safe, c) >= 0:
			b.WriteByte(c)
		case plus && c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, format, c)
		}
	}
	return b.String()
}

// percentVariants returns every percent-encoded rendering of value: each safe
// set in both hex cases, and the form encoding that writes a space as "+".
// A value holding none of the characters the sets differ over collapses to one
// string, so this costs nothing on the ordinary case.
func percentVariants(value string) map[string]bool {
	out := map[string]bool{}
	for _, safe := range []string{safeQuote, safeComponent, safeURI} {
		for _, lower := range []bool{false, true} {
			out[percentEncode(value, safe, false, lower)] = true
			out[percentEncode(value, safe, true, lower)] = true
		}
	}
	return out
}

// shlexUnsafe matches Python's shlex.quote find set: anything outside
// [\w@%+=:,./-] forces quoting.
var shlexUnsafe = regexp.MustCompile(`[^\w@%+=:,./-]`)

// shlexQuote mirrors Python's shlex.quote.
func shlexQuote(value string) string {
	if value == "" {
		return "''"
	}
	if !shlexUnsafe.MatchString(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// jsonEscape returns the JSON string encoding of value without the quotes.
func jsonEscape(value string) string {
	// SetEscapeHTML(false) keeps <, > and & literal, which is what ordinary tools
	// print.
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return value
	}
	s := strings.TrimRight(b.String(), "\n")
	if len(s) >= 2 {
		return s[1 : len(s)-1]
	}
	return s
}

// jsonEscapeASCII is jsonEscape with every non-ASCII rune escaped to \uXXXX.
//
// It exists because Go's encoder is the odd one out: it leaves non-ASCII as
// UTF-8, while Python's json.dumps and PHP's json_encode escape it unless told
// otherwise. A value carrying one accented character is therefore rendered by
// the two most common producers in a form the raw spelling does not match, and
// the ASCII part of it goes out in the clear.
//
// Lower-case hex, which is what all three of JSON.stringify, json.dumps and
// json_encode emit. Astral runes become a surrogate pair, JSON having no other
// spelling for them.
func jsonEscapeASCII(value string) string {
	escaped := jsonEscape(value)
	var b strings.Builder
	b.Grow(len(escaped))
	for _, r := range escaped {
		switch {
		case r < utf8.RuneSelf:
			b.WriteRune(r)
		case r > 0xFFFF:
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// variants returns every rendering of value the redactor recognises. Not
// exhaustive by design (see docs/redaction.md), but the encodings ordinary
// tools produce by accident.
func variants(value string) map[string]bool {
	out := map[string]bool{value: true}
	for v := range base64Variants(value) {
		out[v] = true
	}
	for v := range base32Variants(value) {
		out[v] = true
	}
	// Hex, both cases, contiguous: xxd -p, bytes.hex(), DB BLOB dumps. A
	// dump that separates the bytes is a different string and is not this: see
	// docs/redaction.md.
	h := hex.EncodeToString([]byte(value))
	out[h] = true
	out[strings.ToUpper(h)] = true
	for v := range percentVariants(value) {
		out[v] = true
	}
	js := jsonEscape(value)
	out[js] = true
	// PHP's json_encode and many JSON serializers escape "/" as "\/" by default.
	out[strings.ReplaceAll(js, "/", `\/`)] = true
	// The same two, with non-ASCII escaped: json.dumps and json_encode as they
	// are called with no arguments. Identical to the pair above for an all-ASCII
	// value, and the set deduplicates.
	ja := jsonEscapeASCII(value)
	out[ja] = true
	out[strings.ReplaceAll(ja, "/", `\/`)] = true
	out[shlexQuote(value)] = true
	// Body of a shell single-quoted string.
	out[strings.ReplaceAll(value, "'", `'\''`)] = true
	// Body of a shell double-quoted string.
	dq := strings.ReplaceAll(value, `\`, `\\`)
	dq = strings.ReplaceAll(dq, `"`, `\"`)
	dq = strings.ReplaceAll(dq, `$`, `\$`)
	dq = strings.ReplaceAll(dq, "`", "\\`")
	out[dq] = true

	delete(out, "")
	return out
}

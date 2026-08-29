// Package keeper holds the age key. It decrypts on request and never hands the
// key out, so no process that executes a command can reach it; see
// docs/design.md.
//
// It runs as its own uid and execs nothing but sops. Executed rather than
// linked, which would pull every key source sops supports into the address
// space holding the master key. The key reaches sops as a path
// (SOPS_AGE_KEY_FILE), never as a value, so it is absent from
// /proc/<pid>/environ on both sides.
//
// Fingerprinting lives here because the secrets are group-readable by this uid
// alone; the broker asks what changed rather than looking.
//
// Two ops, get_values and get_state, specified in docs/protocol.md. get_values
// returns every managed value, never a subset, and carries the file state with
// it so a reload is one round trip.
package keeper

import (
	"context"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/fserr"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

const (
	maxRequestBytes = 65536
	decryptTimeout  = 60 * time.Second
	// decryptBudget bounds one get_values across every managed file, so a reply
	// arrives within a time the caller can bound too. keeperclient's own
	// callTimeout is set above this; the two are separate constants because that
	// package shares no code with the one holding the key.
	decryptBudget = 5 * time.Minute
	// How long one peer may take to send its request, and to read the reply once
	// it is ready. Not the time to serve it: decryptTimeout bounds that, per
	// file.
	requestTimeout = 30 * time.Second
)

// Flatten walks decrypted JSON into "path/to/key" -> string pairs.
func Flatten(node any) map[string]string {
	out := map[string]string{}
	flattenNode(node, "", out)
	return out
}

func flattenNode(node any, prefix string, out map[string]string) {
	switch v := node.(type) {
	case map[string]any:
		for key, value := range v {
			// Exactly the top-level "sops" key, sops' own metadata block: a prefix
			// match at any depth would drop real secrets such as sops_backup_token.
			if prefix == "" && key == "sops" {
				continue
			}
			child := key
			if prefix != "" {
				child = prefix + "/" + key
			}
			flattenNode(value, child, out)
		}
	case []any:
		for i, value := range v {
			child := strconv.Itoa(i)
			if prefix != "" {
				child = prefix + "/" + strconv.Itoa(i)
			}
			flattenNode(value, child, out)
		}
	case bool, nil:
		// Never secret, and "true"/"false" would redact half the output.
		return
	case string:
		out[prefix] = v
	case int:
		out[prefix] = strconv.Itoa(v)
	case int64:
		out[prefix] = strconv.FormatInt(v, 10)
	case float64:
		out[prefix] = strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		out[prefix] = v.String()
		// Anything else -- a timestamp a YAML parser typed, a scalar with no JSON
		// shape -- is dropped rather than rendered with %v: a Go rendering is a
		// spelling no tool prints, so it would sit in the redactor matching
		// nothing and be injected as text nothing chose. secretlink's scalar()
		// refuses the same shapes with a reason.
	}
}

// ageSecretKeyRe matches an age identity, so one can be scrubbed from a message
// without the keeper ever reading the file.
var ageSecretKeyRe = regexp.MustCompile(`AGE-SECRET-KEY-[0-9A-Za-z]+`)

// KeyHolder locates the age key file and does not read it: sops opens it
// itself, so the material never exists in this process.
type KeyHolder struct {
	config config.KeeperConfig
	mu     sync.Mutex
	looked bool
	path   string
}

func newKeyHolder(cfg config.KeeperConfig) *KeyHolder { return &KeyHolder{config: cfg} }

// Path returns the age key file to hand sops, or "" if none is available.
func (k *KeyHolder) Path() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.looked {
		return k.path
	}
	k.looked = true

	var candidates []string
	if creds := os.Getenv("CREDENTIALS_DIRECTORY"); creds != "" && k.config.AgeKeyCredential != "" {
		candidates = append(candidates, filepath.Join(creds, k.config.AgeKeyCredential))
	}
	if k.config.AgeKeyFile != "" {
		candidates = append(candidates, k.config.AgeKeyFile)
	}
	for _, candidate := range candidates {
		// Readability, not contents.
		fh, err := os.Open(candidate)
		if err != nil {
			continue
		}
		_ = fh.Close()
		k.path = candidate
		log.Printf("age key available at %s (not read by this process)", candidate)
		return k.path
	}
	log.Printf("no age key available (tried: %s)", strings.Join(candidates, ", "))
	return ""
}

// Scrub removes key material from text, an error string being the one thing
// that crosses from this process to the broker. Matching the age identity
// format rather than a copy of the key is what lets it scrub without holding
// the material.
func (k *KeyHolder) Scrub(text string) string {
	return ageSecretKeyRe.ReplaceAllString(text, "«AGE-KEY»")
}

// FileState is one managed file's identity on disk: enough to notice an edit,
// nothing about its contents. Nanoseconds, a serialisation that rounds turning
// an edit made within the same second into no change.
type FileState struct {
	Path  string `json:"path"`
	MTime int64  `json:"mtime_unix_nano"`
	Size  int64  `json:"size"`
}

// Resolve expands each managed store entry against the filesystem. Every entry
// is a glob, a literal path being one with no metacharacters, and matches are
// deduplicated.
//
// Per request rather than at config load, so a file added beside the others is
// picked up on the next refresh. It is also the only place that can resolve:
// the secrets directory is group-readable by this uid alone.
//
// The two kinds of not-there are returned separately: an entry that named
// nothing is a secrets directory not written yet, and a file that is there and
// will not open is a value the redactor is missing without knowing it. Only
// the second is an error.
func Resolve(files []string) (paths, errors, unresolved []string) {
	paths = []string{}
	errors = []string{}
	unresolved = []string{}
	seen := map[string]bool{}
	for _, entry := range files {
		matches, err := filepath.Glob(entry)
		if err != nil {
			// Only ErrBadPattern, which config rejects at load.
			errors = append(errors, entry+": "+err.Error())
			continue
		}
		if len(matches) == 0 {
			unresolved = append(unresolved, entry+": "+unresolvedReason(entry))
			continue
		}
		for _, match := range matches {
			if seen[match] {
				continue
			}
			seen[match] = true
			paths = append(paths, match)
		}
	}
	// The entries are alternatives rather than an inventory, so "did anything
	// match" belongs to the set. It is asked at all because a store that matched
	// nothing is a broker redacting nothing, which has to be told apart from one
	// whose files have not been written yet.
	if len(paths) > 0 {
		unresolved = []string{}
	}
	return paths, errors, unresolved
}

// NoMatchReason is the reason an entry gives when nothing is wrong with the
// directory and it simply holds no matching file. Exported because a caller
// rendering it adds a guess at why -- not written yet, filesystem not mounted
// -- which belongs only to this one: the others name what stopped them.
const NoMatchReason = "matched no files"

// refusedPrefix opens the reason an entry gives when the directory it names
// could not be read at all.
const refusedPrefix = "cannot read "

// UnresolvedWasRefused reports whether an entry Resolve returned says the
// search was stopped rather than that it found nothing. A caller grades the
// two differently: an empty directory is what every host looks like before its
// first secret is written, and one this account may not read is what no
// working install looks like.
//
// Matched on the reason, which Resolve writes after the entry and ": ". A
// pattern carrying that text itself would read as one of these; the patterns
// are derived from the config directory rather than typed, so there is none to
// carry it.
func UnresolvedWasRefused(entry string) bool {
	_, reason, found := strings.Cut(entry, ": ")
	return found && strings.HasPrefix(reason, refusedPrefix)
}

// unresolvedReason says why an entry named nothing, separating "not written
// yet" from "this process cannot look". The two are corrected differently --
// write a file, or give the account the directory back -- and Glob reports
// neither: it returns no matches and no error either way.
func unresolvedReason(entry string) string {
	if isPattern(entry) {
		// The directory the pattern names, read the way Glob reads it. Skipped
		// where that part is itself a pattern, there being no one directory to
		// name.
		dir := filepath.Dir(entry)
		if isPattern(dir) {
			return NoMatchReason
		}
		if err := readable(dir); err != nil {
			return refusedPrefix + fserr.At(dir, err).Error()
		}
		return NoMatchReason
	}
	if _, err := os.Stat(entry); err != nil {
		return err.Error()
	}
	// Glob uses Lstat and os.Stat follows, so this is a dangling symlink.
	return "no such file"
}

// readable is whether this process could have listed a directory, asked with
// one entry rather than with ReadDir: the answer is the open, and a store that
// matched no *.sops.yml can still hold a great many other files.
func readable(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Close() }()
	if _, err := handle.Readdirnames(1); err != nil && !goerrors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// isPattern reports whether an entry has glob metacharacters. The set filepath
// treats as meta on this platform; a backslash escapes on Unix, so it counts.
func isPattern(entry string) bool { return strings.ContainsAny(entry, `*?[\`) }

// StatAll fingerprints every managed file: no key, no sops, no contents, the
// broker calling this on every poll. A file that cannot be stat-ed is an error
// rather than a missing entry.
func StatAll(secrets config.SecretConfig) ([]FileState, []string, []string) {
	state := []FileState{}
	paths, errors, unresolved := Resolve(secrets.Patterns)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			errors = append(errors, path+": "+err.Error())
			continue
		}
		state = append(state, FileState{
			Path: path, MTime: info.ModTime().UnixNano(), Size: info.Size()})
	}
	return state, errors, unresolved
}

// DecryptAll decrypts every managed file. Per-file failures are returned as
// errors rather than aborting, so one broken file does not blank the value
// set.
//
// The third return is the refs two files define with different values. One
// value wins and the other leaves the value set entirely, so it is injected by
// nothing and redacted by nothing: the same consequence as a value below
// [secret] min_length, and reported the same way rather than left to a daemon
// log line. Two files holding the same value are not this, nothing being lost
// when the one that does not win is byte for byte the one that does.
func DecryptAll(secrets config.SecretConfig, keys *KeyHolder) (map[string]string, []string, map[string]string) {
	values := map[string]string{}
	// Every file that defined each ref, and whether any two of them disagreed
	// about its value.
	definedIn := map[string][]string{}
	disagreed := map[string]bool{}
	paths, errors, _ := Resolve(secrets.Patterns)

	env := []string{
		"PATH=" + envOr("PATH", "/usr/local/bin:/usr/bin:/bin"),
		"HOME=" + envOr("HOME", "/tmp"),
		"LANG=C.UTF-8",
	}
	// The path, never the material: SOPS_AGE_KEY would put the key in the child's
	// environment block, visible in /proc/<pid>/environ.
	if path := keys.Path(); path != "" {
		env = append(env, "SOPS_AGE_KEY_FILE="+path)
	}

	// One budget across the whole set as well as one per file: otherwise the reply
	// is bounded only by len(paths) * decryptTimeout, which no caller knows in
	// advance, and a large enough store would time out on the broker's side while
	// this was still working. Files past the budget report as failures.
	overall, cancelAll := context.WithTimeout(context.Background(), decryptBudget)
	defer cancelAll()

	for _, path := range paths {
		argv := make([]string, 0, len(secrets.DecryptCommand))
		for _, a := range secrets.DecryptCommand {
			argv = append(argv, strings.ReplaceAll(a, "{file}", path))
		}
		if len(argv) == 0 {
			errors = append(errors, path+": [secret] decrypt_command is empty")
			continue
		}

		ctx, cancel := context.WithTimeout(overall, decryptTimeout)
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Env = env
		stdout, err := cmd.Output()
		cancel()

		if err != nil {
			if exitErr, ok := goerrors.AsType[*exec.ExitError](err); ok {
				errors = append(errors, keys.Scrub(fmt.Sprintf(
					"%s: decrypt failed (%d): %s", path, exitErr.ExitCode(),
					firstLine(string(exitErr.Stderr)))))
			} else {
				errors = append(errors, keys.Scrub(fmt.Sprintf(
					"%s: running %s failed: %v", path, argv[0], err)))
			}
			continue
		}

		var tree any
		if err := json.Unmarshal(stdout, &tree); err != nil {
			errors = append(errors, fmt.Sprintf("%s: decrypted output is not JSON: %v", path, err))
			continue
		}
		for ref, value := range Flatten(tree) {
			// Only a ref two files disagree about is shadowed. Two files holding the
			// same value lose nothing: the one that does not win is byte for byte
			// the one that does, so it is in the redactor and injected by the same
			// ref, and reporting it would fail a converge on a host with nothing
			// wrong with it.
			if existing, ok := values[ref]; ok && existing != value {
				log.Printf("secret ref %s defined more than once; last wins", ref)
				disagreed[ref] = true
			}
			definedIn[ref] = append(definedIn[ref], path)
			values[ref] = value
		}
	}
	// Named by the files rather than by a count: the repair is to take the ref
	// out of one of them, so the operator needs to know which two.
	shadowed := map[string]string{}
	for ref := range disagreed {
		// Every file that defines it, not only the two that differed: the repair is
		// to take the ref out of one of them, so the operator needs the whole list.
		shadowed[ref] = "defined in " + strings.Join(definedIn[ref], " and ") +
			", and they do not all hold the same value; the last one read wins and " +
			"the value it displaced is in no redactor"
	}
	return values, errors, shadowed
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// firstLine is the line of a decrypt failure the operator is shown, and it goes
// into `faramir status`, `doctor` and the refusal a brokered command gets.
//
// The first rather than the last: a program's error summary is conventionally
// its opening line, and the closing one is often the tail of an explanation.
// sops ends "In order for SOPS to recover the file, at least one key has to be
// successful, but none were.", so the last line reached the operator as the
// fragment "but none were." and said nothing about which file or why.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output"
	}
	for line := range strings.SplitSeq(s, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return s
}

type Keeper struct {
	config *config.Config
	Keys   *KeyHolder
	ln     net.Listener
}

func New(cfg *config.Config) *Keeper {
	return &Keeper{config: cfg, Keys: newKeyHolder(cfg.Keeper)}
}

func (k *Keeper) Listen() (net.Listener, error) {
	ln, err := sockutil.Listen(k.config.Keeper.SocketPath)
	if err != nil {
		return nil, err
	}
	k.ln = ln
	return ln, nil
}

// Serve handles connections until the listener is closed. Serial: the broker
// is the only client and holds a single-flight latch across a refresh, which is
// what keeps a poll from queueing behind a long get_values.
func (k *Keeper) Serve() error {
	for {
		conn, err := k.ln.Accept()
		if err != nil {
			// A closed listener is how this ends: Close closes it.
			return nil //nolint:nilerr // the close is the stop signal
		}
		k.serveConnection(conn)
	}
}

func (k *Keeper) Close() error {
	if k.ln != nil {
		return k.ln.Close()
	}
	return nil
}

func (k *Keeper) serveConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	// Serve handles one connection at a time, so a peer that connects and then
	// neither sends nor reads would stall every later request. Both directions,
	// which covers the refusals below as well as the read.
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	peer, err := sockutil.PeerCred(conn)
	if err != nil {
		log.Printf("SO_PEERCRED unavailable: %v", err)
		_ = sockutil.Send(conn, sockutil.ErrorResponse("forbidden", "peer not authorized"))
		return
	}
	if !sockutil.AllowedUser(peer, k.config.Keeper.AllowedUser) {
		_ = sockutil.Send(conn, sockutil.ErrorResponse("forbidden", "peer not authorized"))
		return
	}
	line, err := sockutil.ReadLine(conn, maxRequestBytes)
	if err != nil || line == nil {
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(line, &payload); err != nil {
		return
	}
	// Cleared before Handle: get_values execs sops once per managed file, which is
	// not on the same clock as reading one line of JSON.
	_ = conn.SetDeadline(time.Time{})
	response := k.Handle(payload)
	_ = conn.SetWriteDeadline(time.Now().Add(requestTimeout))
	_ = sockutil.Send(conn, response)
}

// Handle dispatches one request.
func (k *Keeper) Handle(payload map[string]any) map[string]any {
	if payload == nil {
		return sockutil.ErrorResponse("bad_request", "request must be a JSON object")
	}
	// Before the op: the broker and the keeper are one binary under two units, so
	// a caller of another release is one of them left running across the install
	// that replaced it. Blocked whatever it asked for, and told which.
	caller, _ := payload["version"].(string)
	if why := version.Mismatch(caller); why != "" {
		return sockutil.ErrorResponse("bad_request", why)
	}
	op, _ := payload["op"].(string)
	switch op {
	case "get_state":
		// The poll: no key, no sops, and unlogged, this running as often as the
		// refresh interval allows.
		state, errs, unresolved := StatAll(k.config.Secret)
		return map[string]any{"state": state, "errors": errs, "unresolved_patterns": unresolved}
	case "get_values":
		// Stat first, so an edit during the decrypt leaves the fingerprint older
		// than the values and reloads once too often. The other order would never
		// pick the edit up.
		state, errs, unresolved := StatAll(k.config.Secret)
		values, decryptErrs, shadowed := DecryptAll(k.config.Secret, k.Keys)
		errs = append(errs, decryptErrs...)
		log.Printf("served %d value(s), %d error(s), %d entry(ies) naming nothing",
			len(values), len(errs), len(unresolved))
		return map[string]any{"values": values, "state": state, "errors": errs,
			"unresolved_patterns": unresolved, "shadowed_refs": shadowed}
	default:
		// Named explicitly, so the error says the key is not obtainable here.
		return sockutil.ErrorResponse("unsupported", fmt.Sprintf(
			"unsupported op %q; the keeper serves 'get_values' and 'get_state' "+
				"only and has no operation that returns key material", op))
	}
}

func SortedRefs(values map[string]string) []string {
	refs := make([]string, 0, len(values))
	for ref := range values {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

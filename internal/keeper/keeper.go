// Package keeper holds the age key.  It decrypts on request, and never hands
// the key out: no process that executes a command can reach the master key.
// See docs/design.md.
//
// It runs as its own uid and execs nothing but sops.  Executed rather than
// linked, which would pull every key source sops supports into the address
// space holding the master key.  The key reaches sops as a path
// (SOPS_AGE_KEY_FILE), never as a value, so it is absent from
// /proc/<pid>/environ on both sides.
//
// Fingerprinting lives here because the store is group-readable by this uid
// alone; the broker asks what changed rather than looking.
//
// Protocol: one line of JSON in, one out, same shape as the broker socket.
//
//	-> {"op": "get_values"}
//	<- {"values": {ref: value, ...}, "state": [...], "errors": [...]}
//	-> {"op": "get_state"}
//	<- {"state": [{"path": ..., "mtime_unix_nano": ..., "size": ...}], "errors": [...]}
//	<- {"error": {"code": ..., "message": ...}}
//
// get_values returns every managed value, never a subset, and carries the state
// with it so a reload is one round trip.
package keeper

import (
	"context"
	"encoding/json"
	goerrors "errors"
	"fmt"
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
	"github.com/andornaut/faramir/internal/sockutil"
)

const (
	maxRequestBytes = 65536
	decryptTimeout  = 60 * time.Second
)

// --------------------------------------------------------------------------
// Flattening
// --------------------------------------------------------------------------

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
			// Exactly the top-level "sops" key, sops' own metadata block.  A
			// prefix match at any depth would drop real secrets
			// (sops_backup_token, home/sopsuser) from the value set.
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
	case float64:
		out[prefix] = strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		out[prefix] = v.String()
	default:
		out[prefix] = fmt.Sprintf("%v", v)
	}
}

// --------------------------------------------------------------------------
// Key location
// --------------------------------------------------------------------------

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

func NewKeyHolder(cfg config.KeeperConfig) *KeyHolder { return &KeyHolder{config: cfg} }

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

// Scrub removes key material from text.  An error string is the one thing that
// crosses from this process to the broker.  Matching the age identity format
// rather than a copy of the key is what lets it scrub without holding the
// material.
func (k *KeyHolder) Scrub(text string) string {
	return ageSecretKeyRe.ReplaceAllString(text, "«AGE-KEY»")
}

// --------------------------------------------------------------------------
// File state
// --------------------------------------------------------------------------

// FileState is one managed file's identity on disk: enough to notice an edit,
// nothing about its contents.  Nanoseconds, because a serialization that rounds
// turns an edit made within the same second into no change.
type FileState struct {
	Path  string `json:"path"`
	MTime int64  `json:"mtime_unix_nano"`
	Size  int64  `json:"size"`
}

// Resolve expands each [secrets] files entry against the filesystem.  Every
// entry is a glob, a literal path being one with no metacharacters, and an
// entry naming no file is an error: unmounted and deleted both leave the broker
// configured for values it does not have.
//
// Per request rather than at config load, so a file added beside the others is
// picked up on the next refresh.  It is also the only place that can resolve:
// the store directory is group-readable by this uid alone.
//
// Deduplicated, since the base config globs the store and a drop-in may name a
// file in it as well.
func Resolve(files []string) ([]string, []string) {
	paths := []string{}
	errors := []string{}
	seen := map[string]bool{}
	for _, entry := range files {
		matches, err := filepath.Glob(entry)
		if err != nil {
			// Only ErrBadPattern, which config rejects at load.
			errors = append(errors, entry+": "+err.Error())
			continue
		}
		if len(matches) == 0 {
			errors = append(errors, entry+": "+unresolvedReason(entry))
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
	return paths, errors
}

// unresolvedReason says why an entry named nothing.  A literal path gets its
// stat error, which separates "not written yet" from "the directory above is
// unreadable".
func unresolvedReason(entry string) string {
	if isPattern(entry) {
		return "matched no files"
	}
	if _, err := os.Stat(entry); err != nil {
		return err.Error()
	}
	// Glob uses Lstat and os.Stat follows, so this is a dangling symlink.
	return "no such file"
}

// isPattern reports whether an entry has glob metacharacters.  The set filepath
// treats as meta on this platform; a backslash escapes on Unix, so it counts.
func isPattern(entry string) bool { return strings.ContainsAny(entry, `*?[\`) }

// StatAll fingerprints every managed file: no key, no sops, no contents, since
// the broker calls this on every poll.  A file that cannot be stat-ed is an
// error rather than a missing entry.
func StatAll(secrets config.SecretsConfig) ([]FileState, []string) {
	state := []FileState{}
	paths, errors := Resolve(secrets.Files)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			errors = append(errors, path+": "+err.Error())
			continue
		}
		state = append(state, FileState{
			Path: path, MTime: info.ModTime().UnixNano(), Size: info.Size()})
	}
	return state, errors
}

// --------------------------------------------------------------------------
// Decryption
// --------------------------------------------------------------------------

// DecryptAll decrypts every managed file.  Per-file failures are returned as
// errors rather than aborting, so one broken file does not blank the value set.
func DecryptAll(secrets config.SecretsConfig, keys *KeyHolder) (map[string]string, []string) {
	values := map[string]string{}
	paths, errors := Resolve(secrets.Files)

	env := []string{
		"PATH=" + envOr("PATH", "/usr/local/bin:/usr/bin:/bin"),
		"HOME=" + envOr("HOME", "/tmp"),
		"LANG=C.UTF-8",
	}
	// The path, never the material: SOPS_AGE_KEY would put the key in the
	// child's environment block, visible in /proc/<pid>/environ.
	if path := keys.Path(); path != "" {
		env = append(env, "SOPS_AGE_KEY_FILE="+path)
	}

	for _, path := range paths {
		argv := make([]string, 0, len(secrets.DecryptCommand))
		for _, a := range secrets.DecryptCommand {
			argv = append(argv, strings.ReplaceAll(a, "{file}", path))
		}
		if len(argv) == 0 {
			errors = append(errors, path+": [secrets] decrypt_command is empty")
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), decryptTimeout)
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Env = env
		stdout, err := cmd.Output()
		cancel()

		if err != nil {
			var exitErr *exec.ExitError
			if goerrors.As(err, &exitErr) {
				errors = append(errors, keys.Scrub(fmt.Sprintf(
					"%s: decrypt failed (%d): %s", path, exitErr.ExitCode(),
					lastLine(string(exitErr.Stderr)))))
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
			if existing, ok := values[ref]; ok && existing != value {
				log.Printf("secret ref %s defined more than once; last wins", ref)
			}
			values[ref] = value
		}
	}
	return values, errors
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output"
	}
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// --------------------------------------------------------------------------
// Server
// --------------------------------------------------------------------------

type Keeper struct {
	config *config.Config
	Keys   *KeyHolder
	ln     net.Listener
}

func New(cfg *config.Config) *Keeper {
	return &Keeper{config: cfg, Keys: NewKeyHolder(cfg.Keeper)}
}

func (k *Keeper) Listen() (net.Listener, error) {
	ln, err := sockutil.Listen(k.config.Keeper.SocketPath, k.config.Keeper.SocketMode)
	if err != nil {
		return nil, err
	}
	k.ln = ln
	return ln, nil
}

// Serve handles connections until the listener is closed.  Serial, because the
// broker is the only client and holds a single-flight latch across a refresh,
// which is what keeps a poll from queueing behind a long get_values.
func (k *Keeper) Serve() error {
	for {
		conn, err := k.ln.Accept()
		if err != nil {
			return nil // listener closed
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
	peer, err := sockutil.PeerCred(conn)
	if err != nil {
		log.Printf("SO_PEERCRED unavailable: %v", err)
		_ = sockutil.Send(conn, errorResponse("forbidden", "peer not authorized"))
		return
	}
	if !sockutil.AllowedUser(peer, k.config.Keeper.AllowedUsers) {
		_ = sockutil.Send(conn, errorResponse("forbidden", "peer not authorized"))
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
	_ = sockutil.Send(conn, k.Handle(payload))
}

// Handle dispatches one request.
func (k *Keeper) Handle(payload map[string]any) map[string]any {
	if payload == nil {
		return errorResponse("bad_request", "request must be a JSON object")
	}
	op, _ := payload["op"].(string)
	switch op {
	case "get_state":
		// The poll: no key, no sops, and unlogged, since with a refresh
		// interval of 0 it runs as often as commands arrive.
		state, errs := StatAll(k.config.Secrets)
		return map[string]any{"state": state, "errors": errs}
	case "get_values":
		// Stat first, so an edit during the decrypt leaves the fingerprint
		// older than the values and reloads once too often.  The other order
		// would never pick the edit up.
		state, errs := StatAll(k.config.Secrets)
		values, decryptErrs := DecryptAll(k.config.Secrets, k.Keys)
		errs = append(errs, decryptErrs...)
		log.Printf("served %d value(s), %d error(s)", len(values), len(errs))
		return map[string]any{"values": values, "state": state, "errors": errs}
	default:
		// Named explicitly, so the error says the key is not obtainable here.
		return errorResponse("unsupported", fmt.Sprintf(
			"unsupported op %q; the keeper serves 'get_values' and 'get_state' "+
				"only and has no operation that returns key material", op))
	}
}

func errorResponse(code, message string) map[string]any {
	return map[string]any{"error": map[string]string{"code": code, "message": message}}
}

// SortedRefs is a helper for --check output.
func SortedRefs(values map[string]string) []string {
	refs := make([]string, 0, len(values))
	for ref := range values {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

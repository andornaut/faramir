// Package keeper holds the age key.  It decrypts on request, and never hands
// the key out.
//
// The keeper exists so that no process which executes a command can reach the
// master key.  Losing one credential means rotating one credential; losing the
// age key means every managed sops file, retroactively, including every
// encrypted blob already in git history.
//
// So it runs as its own uid, execs nothing but sops, and serves exactly one
// operation: return the decrypted ref/value map.  There is deliberately no
// operation that returns the key.  Adding one would defeat the only reason
// this process exists as a separate service.
//
// sops is executed, not linked.  Linking it would pull every key source sops
// supports (AWS KMS, GCP KMS, Azure Key Vault, Vault, PGP) and their
// transitive dependencies into the address space that holds the master key,
// and Go cannot tree-shake them back out.  Keeping sops in a separate
// short-lived process also leaves it upgradable on its own.
//
// The key material reaches sops as a *path*, never as a value: the keeper sets
// SOPS_AGE_KEY_FILE and sops opens the file itself.  Nothing puts the key in
// an environment block, so it is absent from /proc/<pid>/environ on both sides.
//
// Protocol: one line of JSON in, one line of JSON out, same shape as the
// broker socket.
//
//	-> {"op": "get_values"}                  every managed value
//	-> {"op": "get_values", "refs": [...]}   only those refs
//	<- {"values": {ref: value, ...}, "errors": [...]}
//	<- {"error": {"code": ..., "message": ...}}
//
// The refs filter exists so that a later "never resident in the broker" list
// for break-glass credentials is a configuration change rather than a protocol
// change.
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
			// Exactly the top-level "sops" key, which is sops' own metadata
			// block.  A prefix match at any depth would silently drop real
			// secrets (sops_backup_token, home/sopsuser) from the value set,
			// and a dropped secret is never redacted and never warned about.
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

// ageSecretKeyRe matches an age identity, so one can be scrubbed out of a
// message even though the keeper never reads the file.
var ageSecretKeyRe = regexp.MustCompile(`AGE-SECRET-KEY-[0-9A-Za-z]+`)

// KeyHolder locates the age key file.  It deliberately does not read it: sops
// opens the file itself, so the material need not exist in this process at all.
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
		// Readability, not contents: opening and closing proves sops will be
		// able to read it without this process ever holding the material.
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

// Scrub removes key material from text.
//
// sops should never print the key back at us, but an error string is the one
// thing that crosses from this process to the broker, and the whole point of
// the split is that the key does not make that trip.  Matching the age
// identity format rather than a copy of the key is what lets the keeper scrub
// without ever holding the material.
func (k *KeyHolder) Scrub(text string) string {
	return ageSecretKeyRe.ReplaceAllString(text, "«AGE-KEY»")
}

// --------------------------------------------------------------------------
// Decryption
// --------------------------------------------------------------------------

// DecryptAll decrypts every managed file.  Per-file failures are returned as
// errors rather than aborting, so one broken file does not blank the value set.
func DecryptAll(secrets config.SecretsConfig, keys *KeyHolder) (map[string]string, []string) {
	values := map[string]string{}
	var errors []string

	env := []string{
		"PATH=" + envOr("PATH", "/usr/local/bin:/usr/bin:/bin"),
		"HOME=" + envOr("HOME", "/tmp"),
		"LANG=C.UTF-8",
	}
	// The path, never the material.  SOPS_AGE_KEY would put the key itself in
	// the child's environment block, where /proc/<pid>/environ exposes it for
	// the lifetime of the process.
	if path := keys.Path(); path != "" {
		env = append(env, "SOPS_AGE_KEY_FILE="+path)
	}

	for _, path := range secrets.Files {
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

// Serve handles connections until the listener is closed.
//
// The keeper answers one client (the broker), rarely: on startup, on SIGHUP,
// and when a managed file changes on disk.  Serial handling is therefore
// enough, and it keeps the process that holds the key as small as it can be.
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
	defer conn.Close()
	peer, err := sockutil.PeerCred(conn)
	if err != nil {
		log.Printf("SO_PEERCRED unavailable: %v", err)
		_ = sockutil.Send(conn, errorResponse("forbidden", "peer not authorized"))
		return
	}
	if !sockutil.AllowedByUsersOrGroups(peer, k.config.Keeper.AllowedUsers, k.config.Keeper.AllowedGroups) {
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

// Handle dispatches one request.  get_values is the only operation.
func (k *Keeper) Handle(payload map[string]any) map[string]any {
	if payload == nil {
		return errorResponse("bad_request", "request must be a JSON object")
	}
	op, _ := payload["op"].(string)
	if op != "get_values" {
		// Named explicitly rather than "unknown op": someone reading this error
		// should learn that the key is not obtainable here, not go looking for
		// the operation that returns it.
		return errorResponse("unsupported", fmt.Sprintf(
			"unsupported op %q; the keeper serves 'get_values' only and has no "+
				"operation that returns key material", op))
	}

	var filter map[string]bool
	if raw, ok := payload["refs"]; ok && raw != nil {
		list, isList := raw.([]any)
		if !isList {
			return errorResponse("bad_request", "'refs' must be a list of strings")
		}
		filter = map[string]bool{}
		for _, r := range list {
			s, isStr := r.(string)
			if !isStr {
				return errorResponse("bad_request", "'refs' must be a list of strings")
			}
			filter[s] = true
		}
	}

	values, errs := DecryptAll(k.config.Secrets, k.Keys)
	if filter != nil {
		for ref := range values {
			if !filter[ref] {
				delete(values, ref)
			}
		}
	}
	log.Printf("served %d value(s), %d error(s)", len(values), len(errs))
	if errs == nil {
		errs = []string{}
	}
	return map[string]any{"values": values, "errors": errs}
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

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
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	"github.com/andornaut/faramir/internal/config"
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

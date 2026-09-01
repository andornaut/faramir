package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/auditview"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sopsrule"
	"github.com/andornaut/faramir/internal/vault"
)

// Re-encrypting the managed store to what `.sops.yaml` says, which is the
// second half of every recipient change and the whole of `recipient reseal`.
// What that is for is docs/operating.md.
//
// It walks the managed files rather than leaving the operator to run `sops
// updatekeys` per file, which rewrites in place with no regard for ownership: a
// managed file that stops being readable by the secrets group is one the keeper
// cannot open. Ownership is preserved by the same writeBack an edit uses, and
// each file is recorded in the audit log.
//
// It runs as root for the same reason edit does: the age key is readable by the
// keeper and by root, and re-encrypting means decrypting first.

// storeContext is what any command that re-encrypts the managed store needs:
// where this install keeps its config, its rule and its key, and which files the
// run is to reach.
type storeContext struct {
	cfg      *config.Config
	keyPath  string
	rulePath string
	targets  []string
}

// loadStore is the preamble every such command shares. It returns nil and an
// exit code where the run cannot proceed, having already said why.
//
// label is how the command names itself in its messages, so an operator reading
// a failure sees the command they ran. emptyStoreOK says whether a store
// naming no file yet is a reason to stop: it is for `reseal`, whose whole job
// is files, and not for a recipient change, the rule governing what sops writes
// from now on.
func loadStore(label, socket string, named []string,
	emptyStoreOK bool) (*storeContext, int) {
	// Blocked rather than attempted, like edit: as the operator this fails on the
	// age key with a bare permission error.
	if !requireRoot(label) {
		return nil, 1
	}
	cfg, err := loadResolved(socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return nil, 1
	}

	keyPath := vault.AgeKeyPath(cfg)
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: age key: %v\n", label, err)
		return nil, 1
	}

	// Both kinds together: this is printed when the named file is not among the
	// managed ones, and the operator wants every reason.
	managed, failures, absent := keeper.Resolve(cfg.Secret.Patterns)
	unresolvable := slices.Concat(failures, absent)
	targets, err := vault.ResealTargets(managed, named)
	if err != nil && emptyStoreOK && errors.Is(err, vault.ErrNoFilesToReseal) {
		// Said once, and the per-pattern reasons dropped with it: each is "this glob
		// matched nothing", which reads as three problems on a host whose first
		// secret has not been written.
		fmt.Fprintf(os.Stderr, "faramir %s: the managed store names no file yet, so "+
			"there is nothing to re-encrypt\n", label)
		return &storeContext{
			cfg:      cfg,
			keyPath:  keyPath,
			rulePath: filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml"),
		}, 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		for _, reason := range unresolvable {
			fmt.Fprintf(os.Stderr, "  %s\n", reason)
		}
		return nil, 1
	}
	// Reported even when enough resolved to proceed, unlike edit, which opens the
	// one file it was asked for: here a pattern that named nothing is a managed
	// file this run did not reach.
	for _, reason := range unresolvable {
		fmt.Fprintf(os.Stderr, "faramir %s: not reached: %s\n", label, reason)
	}

	// This install's own rule, and no flag naming another: these commands make
	// the ciphertext agree with <config-dir>/.sops.yaml, so a run sealing the
	// secrets directory to another file's recipients produces the state they
	// exist to remove. FARAMIR_CONFIG moves the whole install.
	return &storeContext{
		cfg:      cfg,
		keyPath:  keyPath,
		rulePath: filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml"),
		targets:  targets,
	}, 0
}

// resealStore re-encrypts every target to wanted.
func resealStore(label string, store *storeContext, wanted []string, dryRun bool) int {
	targets := store.targets
	if len(targets) == 0 {
		return 0
	}
	log := audit.NewLog(store.cfg.Audit)
	failed, changed := 0, 0
	for _, target := range targets {
		was, err := sopsrule.SealedTo(target)
		if err != nil {
			// Recorded like every other outcome of this loop: a file this run could
			// not read is one it did not reach, and a log silent about it reads as a
			// reseal that covered the whole secrets directory. Not on a dry run,
			// which does nothing to this host.
			if !dryRun {
				log.Write(map[string]any{
					"op": auditview.OpReseal, "log_id": audit.NewLogID(), "file": target,
					"error": err.Error(),
					"uid":   os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
				}, audit.Output{})
			}
			fmt.Fprintf(os.Stderr, "faramir %s: %s: %v\n", label, target, err)
			failed++
			continue
		}
		if sopsrule.Same(was, wanted) {
			fmt.Fprintf(os.Stderr, "faramir %s: unchanged %s\n", label, target)
			continue
		}
		if dryRun {
			fmt.Fprintf(os.Stderr, "faramir %s: would re-encrypt %s: %s -> %s\n",
				label, target, strings.Join(was, ","), strings.Join(wanted, ","))
			changed++
			continue
		}

		err = vault.Reencrypt(store.keyPath, store.rulePath, wanted, target)
		// One record per file, naming the recipients on both sides and never the
		// values: who can read the secrets directory is what an operator needs the
		// log to answer afterwards.
		record := map[string]any{
			"op": auditview.OpReseal, "log_id": audit.NewLogID(), "file": target,
			"from": was, "to": wanted,
			"uid": os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
		}
		if err != nil {
			record["error"] = err.Error()
		}
		log.Write(record, audit.Output{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir %s: %s: %v\n", label, target, err)
			failed++
			continue
		}
		fmt.Fprintf(os.Stderr, "faramir %s: re-encrypted %s: %s -> %s\n",
			label, target, strings.Join(was, ","), strings.Join(wanted, ","))
		changed++
	}

	// Named rather than left implicit: a reseal that reached only some of the
	// files leaves the rest sealed to the old recipients.
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "faramir %s: %d of %d file(s) could not be re-encrypted; "+
			"those still open to the recipients they had\n", label, failed, len(targets))
		return 1
	}
	if dryRun {
		fmt.Fprintf(os.Stderr, "faramir %s: %d of %d file(s) would change\n", label, changed, len(targets))
		return 0
	}
	if changed > 0 {
		fmt.Fprintf(os.Stderr, "faramir %s: %d of %d file(s) re-encrypted; %s\n",
			label, changed, len(targets),
			reReadNote(tellBrokerToReRead(), "it picks them up within one refresh interval"))
	}
	return 0
}

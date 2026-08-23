package install

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/config"
)

// stepAdopted names what this run took from the install it found, before
// anything is written with it. Silent on a first install and on one that named
// every default.
func (r *runner) stepAdopted() error {
	if len(r.adopted) == 0 {
		return nil
	}
	r.step("adopted", false, strings.Join(r.adopted, ", "))
	return nil
}

// adoptInstalled fills what the operator did not name from the install this run
// is about to re-provision, and reports what it took. config.toml is rendered
// from these values on every run, so a flag left out would revert the install:
// without --client-group the run rewrites allowed_group and shuts the named
// group out of the broker socket, and without --ssh-key it mints a key no
// managed host authorizes.
//
// Each value has one source, the one doctor reads: the accounts from the units'
// own User=, the client group and the key from the installed config, the
// secrets group from the directory it owns. A flag still wins.
//
// A host with no units and no config is the first install. A config that is
// there and does not load stops the run.
func (o *Options) adoptInstalled() (took []string, err error) {
	dir := o.ConfigDir
	if dir == "" {
		dir = DefaultConfigDir
	}
	// Recorded only where the adopted value differs from the default: the report
	// is what a flag would have reverted.
	keep := func(flag, adopted, otherwise string) {
		if adopted != otherwise {
			took = append(took, flag+" "+adopted)
		}
	}
	for _, role := range []struct {
		unit     string
		into     *string
		flag     string
		fallback string
	}{
		{brokerUnit, &o.BrokerUser, "--broker-user", DefaultBrokerUser},
		{keeperUnit, &o.KeeperUser, "--keeper-user", DefaultKeeperUser},
		{execUnit, &o.ExecUser, "--exec-user", DefaultExecUser},
	} {
		if *role.into != "" {
			continue
		}
		account, err := unitUser(role.unit)
		if err != nil {
			continue
		}
		*role.into = account
		keep(role.flag, account, role.fallback)
	}

	// An absent config is the first install. One that is there and does not parse
	// is a broken install and a reason to stop whether or not this run needed
	// anything out of it: no daemon can load it either, and writing over it would
	// replace what says why.
	if err := o.adoptFromConfig(dir, keep); err != nil {
		return nil, err
	}

	// After the keeper's account, the secrets group defaulting to that account's
	// own group.
	if o.SecretsGroup == "" {
		fallback := o.KeeperUser
		if fallback == "" {
			fallback = DefaultKeeperUser
		}
		if group, groupErr := groupOf(filepath.Join(dir, "secrets")); groupErr == nil {
			o.SecretsGroup = group
			keep("--secrets-group", group, fallback)
		}
	}
	return took, nil
}

// adoptFromConfig takes the client group and the SSH key off the installed
// config, those being the two values only it records.
func (o *Options) adoptFromConfig(dir string, keep func(flag, adopted, otherwise string)) error {
	configFile := filepath.Join(dir, "config.toml")
	cfg, err := config.Load(configFile)
	if err != nil {
		if _, statErr := os.Stat(configFile); errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%s is what this install named, and it does not load: %w\n"+
			"No daemon can load it either, so this host is serving nothing, and "+
			"re-provisioning over it would replace what says why. Fix the file, or "+
			"remove it to install fresh", configFile, err)
	}
	if o.ClientGroup == "" && cfg.Server.AllowedGroup != "" {
		o.ClientGroup = cfg.Server.AllowedGroup
		keep("--client-group", o.ClientGroup, DefaultClientGroup)
	}
	if o.SSHKey == "" && cfg.Ssh.Key != "" {
		o.SSHKey = cfg.Ssh.Key
		keep("--ssh-key", o.SSHKey, filepath.Join(dir, "id_ed25519"))
	}
	// The tunables, each kept unless a flag named one. Zero is the unset signal,
	// and `faramir init`'s own flags are blanked before they arrive here when the
	// operator did not type them, which is what makes a bare re-run keep the
	// install rather than reverting it.
	for _, tunable := range []struct {
		into  *int
		found int
	}{
		{&o.CommandTimeoutSec, cfg.Command.TimeoutSec},
		{&o.CommandMaxTimeoutSec, cfg.Command.MaxTimeoutSec},
		{&o.CommandConcurrency, cfg.Command.Concurrency},
		{&o.CommandMaxMemoryPercent, cfg.Command.MaxMemoryPercent},
		{&o.CommandMaxProcessMemoryMB, cfg.Command.MaxProcessMemoryMB},
		{&o.EscalationTimeoutSec, cfg.Escalation.TimeoutSec},
		{&o.SecretMinLength, cfg.Secret.MinLength},
		{&o.SecretMinRefreshSec, cfg.Secret.MinRefreshSec},
	} {
		if *tunable.into == 0 {
			*tunable.into = tunable.found
		}
	}
	// The environment merges the other way round: what the file holds first, then
	// what a flag names on top, so naming one variable keeps the rest. The
	// built-in table is the floor either way, applyDefaults laying it under this:
	// a variable deleted from config.toml by hand comes back on the next run, as
	// every other rendered value does.
	env := map[string]string{}
	maps.Copy(env, cfg.Command.Env)
	maps.Copy(env, o.CommandEnv)
	o.CommandEnv = env

	// The links this file declares. Adoption in the same sense the others are: a
	// re-run keeps what the install already has. Unlike them no flag reaches it,
	// `faramir link` being what changes the list, and this is what stops a plain
	// `init` from erasing it.
	links, err := config.BaseLinks(configFile)
	if err != nil {
		return fmt.Errorf("%s: %w", configFile, err)
	}
	if !o.linksSet {
		o.links = links
	}
	// The blocked paths, kept across a re-run for the same reason and by the
	// same rule: no flag names one, so an `init` that did not read them back
	// would drop every deny rule `faramir block` had added.
	blocked, err := config.BaseBlocked(configFile)
	if err != nil {
		return fmt.Errorf("%s: %w", configFile, err)
	}
	if !o.blockedSet {
		o.blocked = blocked
	}
	return nil
}

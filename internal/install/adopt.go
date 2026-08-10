package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/config"
)

// stepAdopted names what this run took from the install it found, so the values
// a flag would have overridden are visible before anything is written with them.
// Silent when there is nothing to say, which is the first install and the one
// that named every default.
func (r *runner) stepAdopted() error {
	if len(r.adopted) == 0 {
		return nil
	}
	r.step("adopted", false, strings.Join(r.adopted, ", "))
	return nil
}

// adoptInstalled fills what the operator did not name from the install this run
// is about to re-provision, and reports what it took.
//
// config.toml is rendered from these values on every run, and a drop-in may not
// set them, so a flag left out reverts what an earlier install was told rather
// than leaving it alone: without --client-group the run rewrites allowed_group
// to the compiled-in default and shuts every member of the named group out of
// the broker socket, and without --ssh-key it renders the default path and mints
// a key there that no managed host authorizes.
//
// Each value has one source, which is the one doctor reads: the accounts from
// the units' own User=, the client group and the key from the installed config,
// the secrets group from the directory it owns.  A flag still wins, that being
// how any of them is changed.
//
// A host with no units and no config is the first install, which is the case the
// compiled-in defaults exist for.  A config that is there and does not load
// stops the run, whatever this one was given: see below.
func (o *Options) adoptInstalled() (took []string, err error) {
	dir := o.ConfigDir
	if dir == "" {
		dir = DefaultConfigDir
	}
	// Recorded only where the adopted value is not what the defaults would have
	// produced anyway: the report is what a flag would have reverted, and on an
	// install that took every default there is nothing to say.
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
		{"faramir-broker.service", &o.BrokerUser, "--broker-user", DefaultBrokerUser},
		{"faramir-keeper.service", &o.KeeperUser, "--keeper-user", DefaultKeeperUser},
		{"faramir-exec.service", &o.ExecUser, "--exec-user", DefaultExecUser},
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

	// An absent config is the first install.  Anything else there and unreadable is
	// refused rather than defaulted over: this run would render the client group
	// and the key from the compiled-in defaults, which on an install that named
	// others locks a group out of the broker socket and mints a key no managed
	// host authorizes.  Silently reverting an install because its config no longer
	// parses is worse than stopping, and the file is the operator's to fix or
	// remove.
	// Read whatever this run was given: a config that does not parse is a broken
	// install, and that is a reason to stop whether or not this run needed
	// anything out of it.  The daemons cannot load it either, so the host is not
	// serving, and writing over it would replace the evidence of why.
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
	return nil
}

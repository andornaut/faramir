package install

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/asaccount"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/sopsrule"
	"github.com/andornaut/faramir/internal/sshkey"
)

// brokerGroupName is the group a chown in an error message has to name, looked
// up from the gid this run resolved rather than assumed to share the account's
// name. Falls back to the account name, so the remedy is never printed with an
// empty field.
func (r *runner) brokerGroupName() string {
	if group, err := user.LookupGroupId(strconv.Itoa(r.brokerGID)); err == nil {
		return group.Name
	}
	return r.layout.BrokerUser
}

// stepAgeKey mints the keeper's identity, 0400 owned by the keeper: a key the
// broker or the executor could read is one any brokered command could read.
// The keeper takes it through systemd's LoadCredential=.
func (r *runner) stepAgeKey() error {
	// Nothing is opened under a dry run: the key is 0400 and the keeper's, so the
	// recipient is left unknown and the sops step reports it as such.
	if r.opts.DryRun {
		r.reportPresence("age key", r.layout.AgeKeyPath, "mint")
		return nil
	}
	recipient, created, err := agekey.Generate(r.layout.AgeKeyPath)
	if err != nil {
		return err
	}
	// Re-asserted every run, so a key placed by hand ends up keeper-owned.
	changed := created
	if !r.opts.DryRun {
		info, err := os.Stat(r.layout.AgeKeyPath)
		if err != nil {
			return err
		}
		wrong, err := hostfs.WrongOwner(info, r.keeperUID, r.keeperGID)
		if err != nil {
			return err
		}
		if wrong || info.Mode().Perm() != 0o400 {
			if err := os.Chown(r.layout.AgeKeyPath, r.keeperUID, r.keeperGID); err != nil {
				return err
			}
			if err := os.Chmod(r.layout.AgeKeyPath, 0o400); err != nil {
				return err
			}
			changed = true
		}
	}
	r.keeperRecipient = recipient
	r.step("age key", changed, fmt.Sprintf("%s, 0400 %s", r.layout.AgeKeyPath, r.layout.KeeperUser))
	return nil
}

// stepSopsConfig writes .sops.yaml into the config directory rather than the
// secrets directory: sops resolves it from the working directory upward, so it
// is found from both. Written once, sealed to the keeper's own recipient, and
// kept on every later run: adding or dropping a recipient means re-encrypting
// every managed value, which `faramir reader add` does and an installer
// should not.
func (r *runner) stepSopsConfig() error {
	path := r.layout.SopsConfigPath()
	if hostfs.Exists(path) {
		// The contents are kept (see keepSopsConfig) but the mode and ownership are
		// re-asserted: an operator-created file left operator-writable lets the
		// account the secrets group exists to keep out choose the recipients of
		// everything written from then on.
		if _, err := r.fs.EnsureOwnership(path, 0o644, 0, 0); err != nil {
			return err
		}
		r.keepSopsConfig(path)
		return nil
	}
	// A dry run does not open the age key. Named before the check below, which
	// reaches the same empty string by the key having been lost and would print a
	// remedy that is nonsense here.
	if r.opts.DryRun {
		r.skip("sops config", "dry run: the keeper's recipient is not read, so what "+
			"would be written to "+path+" is not computed")
		return nil
	}
	// Never without the keeper's own recipient: a rule listing only the operator
	// produces a secrets directory the keeper cannot read, and a broker that
	// serves nothing.
	if r.keeperRecipient == "" {
		r.skip("sops config", "the keeper's recipient is unknown, because "+
			r.layout.AgeKeyPath+" has been removed. Copy .sops.yaml from a host "+
			"that has it, or re-seal from the original key")
		return nil
	}
	body := "# Which files sops encrypts, and to whom. Any *.sops.yml, wherever it sits:\n# a rule naming one layout refuses to encrypt a file kept anywhere else, and\n# reports it as \"no matching creation rules found\".\n# sops encrypts values and leaves keys readable, so diffs stay per-key and\n# reviewable. 'faramir vault edit' and 'faramir reader reseal' read this file to decide the\n# shape of what they write back, so a key added here governs them too.\ncreation_rules:\n  - path_regex: \\.sops\\.ya?ml$\n    key_groups:\n" +
		"      - age:\n          - " + r.keeperRecipient + "\n"
	// Root-owned like the rest of the config directory, or the recipients could
	// be rewritten by an account the secrets group exists to keep out.
	// World-readable, holding public keys and a rule and no value.
	changed, err := r.fs.WriteFile(path, []byte(body), 0o644, 0, 0)
	if err != nil {
		return err
	}
	r.report.AgeRecipients = []string{r.keeperRecipient}
	// The one run that creates this file, so the one place to say how a second
	// key gets in: sealed to this host alone, a backup of the ciphertext opens
	// with nothing but the key beside it.
	r.step("sops config", changed, fmt.Sprintf("%s, sealed to %s alone; "+
		"`faramir reader add KEY` grants a key that opens it without this host's",
		path, r.layout.KeeperUser))
	return nil
}

// keepSopsConfig leaves an existing .sops.yaml alone and says what it says,
// applying a changed rule meaning every managed value is re-encrypted. The one
// thing it reports is a rule the keeper is not named in; that is a host which
// works today and cannot take a new value tomorrow, so it warns rather than
// failing the run.
func (r *runner) keepSopsConfig(path string) {
	listed, err := sopsrule.AllRecipients(path)
	if err != nil {
		// The file is the operator's to edit and sops is what parses it, so a shape
		// this does not understand is a question that went unasked.
		r.warnf("%s could not be read (%v), so who can decrypt the secrets directory went "+
			"unchecked. sops has to parse this file too: where it cannot, encrypting a new "+
			"value fails", path, err)
		r.step("sops config", false, "keeping "+path)
		return
	}
	// What the file says: nothing else asks for a recipient, `faramir reader
	// add` being what changes one.
	r.report.AgeRecipients = listed

	if r.keeperRecipient != "" && !slices.Contains(listed, r.keeperRecipient) {
		r.warnf("%s does not list the keeper's own recipient (%s), so every value encrypted from "+
			"now on is one %s cannot decrypt. Put it back with:\n  sudo faramir reader add "+
			"%s\nwhich re-seals the store to it. That works while the managed files still open "+
			"with %s",
			path, r.keeperRecipient, r.layout.KeeperUser,
			r.keeperRecipient, r.layout.AgeKeyPath)
	}

	r.step("sops config", false, fmt.Sprintf("keeping %s, %d recipient(s)", path, len(listed)))
}

// stepSSHKey mints the identity the broker lends to brokered commands, and
// asserts that the broker can read it. A key opens a host only once its public
// half is in that host's authorized_keys, which this does not do. An existing
// key at the path is adopted rather than replaced: regenerating one locks the
// broker out of every host it is already on.
//
// Runs after stepConfig, so the file naming the key is already written, and
// before anything starts a daemon.
func (r *runner) stepSSHKey() error {
	if r.opts.DryRun {
		r.reportPresence("broker ssh key", r.layout.SSHKey, "mint")
		return nil
	}
	// own=false: the directory may be the config directory, which is root's, or
	// one the operator made to hold a key of their own.
	if _, err := r.fs.EnsureDir(filepath.Dir(r.layout.SSHKey), 0o700,
		r.brokerUID, r.brokerGID, false); err != nil {
		return err
	}
	host, _ := os.Hostname()
	public, minted, err := sshkey.Generate(r.layout.SSHKey, "faramir broker on "+host)
	if err != nil {
		return err
	}
	r.report.BrokerPublicKey = public
	r.sshKey = r.layout.SSHKey
	// Repaired only when this run wrote it: a key minted by an earlier run is
	// already broker-owned, and one that is not is a key the operator brought,
	// which chowning would take away from them.
	repaired, err := r.ownSSHKey(r.sshKey, minted)
	if err != nil {
		return err
	}
	if minted || repaired {
		r.restartFor("ssh key")
	}
	r.step("broker ssh key", minted || repaired, r.sshKey)
	return nil
}

// sshKeyHalf is one of the two files the broker has to be able to read, with
// the mode it must have.
type sshKeyHalf struct {
	path string
	mode os.FileMode
}

// sshKeyHalves is the pair, private first.
func sshKeyHalves(path string) []sshKeyHalf {
	return []sshKeyHalf{{path, 0o600}, {path + ".pub", 0o644}}
}

// checkSSHKey reports why the broker could not use the key at this path, or
// nil. Split out from ownSSHKey so stepPreconditions can raise the same
// refusal before any ownership is changed: stopping at the SSH step would leave
// the age key and the audit log already handed to accounts whose units were
// never written.
func (r *runner) checkSSHKey(path string, uid, gid int) error {
	return wrongSSHKeyHalves(path, uid, gid, func(half sshKeyHalf) error {
		// Both halves in the remedy, and the group in the chown: this compares uid
		// and gid, so a remedy naming the owner alone would leave the same refusal
		// standing.
		return fmt.Errorf("%s is %s, and [ssh] key names it, so %s cannot load it and brokered commands "+
			"reach no managed host. Hand both halves over:\n    chown %s:%s %s %s\n    chmod "+
			"0600 %s && chmod 0644 %s\nOr unset [ssh] key",
			half.path, asaccount.OwnsWithGroup(half.path), r.layout.BrokerUser,
			r.layout.BrokerUser, r.brokerGroupName(), path, path+".pub",
			path, path+".pub")
	})
}

// wrongSSHKeyHalves visits each half of the key that is not held at uid, gid
// and its own mode. The stat and the comparison are shared by the check and
// the repair, which differ only in what visit does to a wrong half.
func wrongSSHKeyHalves(path string, uid, gid int, visit func(half sshKeyHalf) error) error {
	for _, half := range sshKeyHalves(path) {
		info, err := os.Stat(half.path)
		if err != nil {
			return fmt.Errorf("%s: %w\nThe broker needs both halves of the key. "+
				"Regenerate the public half with: ssh-keygen -y -f %s > %s",
				half.path, err, path, path+".pub")
		}
		wrong, err := hostfs.WrongOwner(info, uid, gid)
		if err != nil {
			return err
		}
		if !wrong && info.Mode().Perm() == half.mode.Perm() {
			continue
		}
		if err := visit(half); err != nil {
			return err
		}
	}
	return nil
}

// ownSSHKey asserts, every run, that the broker can read both halves of the
// key: one placed by hand or left root-owned leaves the agent holding nothing.
// A repair counts as a change. repair is false for a key this run did not
// write, which is refused rather than taken over.
func (r *runner) ownSSHKey(path string, repair bool) (bool, error) {
	if !repair {
		return false, r.checkSSHKey(path, r.brokerUID, r.brokerGID)
	}
	changed := false
	err := wrongSSHKeyHalves(path, r.brokerUID, r.brokerGID, func(half sshKeyHalf) error {
		// Path-based, so a key kept behind a symlink is repaired at its target,
		// which is the file [ssh] key means.
		if err := os.Chown(half.path, r.brokerUID, r.brokerGID); err != nil {
			return err
		}
		if err := os.Chmod(half.path, half.mode); err != nil {
			return err
		}
		changed = true
		return nil
	})
	return changed, err
}

package install

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/sshkey"
)

// brokerGroupName is the group a chown in an error message has to name, looked
// up from the gid this run resolved rather than assumed to share the account's
// name.  Falls back to the account name, which is what useradd would have made
// it, so the remedy is never printed with an empty field.
func (r *runner) brokerGroupName() string {
	if group, err := user.LookupGroupId(strconv.Itoa(r.brokerGID)); err == nil {
		return group.Name
	}
	return r.layout.BrokerUser
}

// stepAgeKey mints the keeper's identity, 0400 owned by the keeper: a key the
// broker or the executor could read is one any brokered command could read. The
// keeper takes it through systemd's LoadCredential=.
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
		wrong, err := wrongOwner(info, r.keeperUID, r.keeperGID)
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
	r.addRecipient(recipient)
	r.step("age key", changed, fmt.Sprintf("%s, 0400 %s", r.layout.AgeKeyPath, r.layout.KeeperUser))
	return nil
}

// addRecipient records an age recipient for .sops.yaml, in a stable order.
func (r *runner) addRecipient(recipient string) {
	if recipient == "" || slices.Contains(r.opts.AgeRecipients, recipient) {
		return
	}
	r.opts.AgeRecipients = append(r.opts.AgeRecipients, recipient)
}

// stepSopsConfig writes .sops.yaml into the config directory rather than the
// secrets: sops resolves it from the working directory upward, so the parent is
// found from both, and the secrets directory is a glob target where
// filepath.Glob matches dotfiles.
//
// Kept if it already exists, adding or dropping a recipient meaning every
// managed value is re-encrypted.  Kept and read back (see keepSopsConfig), so
// --recipient does not silently mean nothing.
func (r *runner) stepSopsConfig() error {
	path := r.layout.SopsConfigPath()
	if exists(path) {
		// The contents are kept (see keepSopsConfig) but the mode and ownership are
		// re-asserted, not merely set at creation: an operator-created file left
		// operator-writable lets the account the secrets group exists to keep out
		// choose the recipients of everything written from then on.
		if _, err := r.fs.ensureOwnership(path, 0o644, 0, 0); err != nil {
			return err
		}
		r.keepSopsConfig(path)
		return nil
	}
	if len(r.opts.AgeRecipients) == 0 {
		r.skip("sops config", "no age recipient known yet")
		return nil
	}
	// A dry run does not open the age key.  Named before the check below, which
	// reaches the same empty string by the key having been lost and prints a
	// remedy that would be nonsense here.
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
	var recipients strings.Builder
	for _, recipient := range r.opts.AgeRecipients {
		fmt.Fprintf(&recipients, "          - %s\n", recipient)
	}
	body := "# Which files sops encrypts, and to whom.  Any *.sops.yml, wherever it sits:\n# a rule naming one layout refuses to encrypt a file kept anywhere else, and\n# reports it as \"no matching creation rules found\".\n# sops encrypts values and leaves keys readable, so diffs stay per-key and\n# reviewable.  'faramir secrets edit' and 'faramir recipient reseal' read this file to decide the\n# shape of what they write back, so a key added here governs them too.\ncreation_rules:\n  - path_regex: \\.sops\\.ya?ml$\n    key_groups:\n      - age:\n" + recipients.String()
	// Root-owned like the rest of the config directory, or the recipients could be
	// rewritten by an account the secrets group exists to keep out.
	// World-readable, holding public keys and a rule and no value.
	changed, err := r.fs.writeFile(path, []byte(body), 0o644, 0, 0)
	if err != nil {
		return err
	}
	r.report.AgeRecipients = slices.Clone(r.opts.AgeRecipients)
	r.step("sops config", changed, fmt.Sprintf("%s, %d recipient(s)", path, len(r.opts.AgeRecipients)))
	return nil
}

// keepSopsConfig leaves an existing .sops.yaml alone and says what it says.
// Applying a changed rule means re-encrypting every managed value, which would
// drop a reader mid-run.
//
// So it is kept, read back, and every difference between what was asked for and
// what is in the file is reported.  Nothing here fails the run: each is a host
// that works today and is wrong about who can read it tomorrow.
func (r *runner) keepSopsConfig(path string) {
	listed, err := sopsRecipients(path)
	if err != nil {
		// The file is the operator's to edit and sops is what parses it, so a shape
		// this does not understand is a question that went unasked.
		r.warnf("%s could not be read (%v), so who can decrypt the secrets directory went "+
			"unchecked. sops is what has to parse this file: if it cannot either, "+
			"encrypting a new value into the secrets directory fails", path, err)
		r.step("sops config", false, "keeping "+path)
		return
	}
	// What the file says, not what was asked for: on every run but the first the
	// request had no part in it.
	r.report.AgeRecipients = listed

	// The keeper's first and separately: the others are a key that does not open
	// the secrets directory, this one is a secrets directory the keeper cannot
	// open.  Skipped when the recipient is unknown, which is reported where it
	// happens.
	if r.keeperRecipient != "" && !slices.Contains(listed, r.keeperRecipient) {
		r.warnf("%s does not list the keeper's own recipient (%s), so every value "+
			"encrypted into the secrets directory from now on is one %s cannot decrypt: the broker "+
			"starts, loads nothing, and redacts nothing. This is what replacing %s "+
			"leaves behind. Add it under `- age:` and re-key the existing files:\n"+
			"  sudoedit %s\n"+
			"  sudo SOPS_AGE_KEY_FILE=%s sops updatekeys %s/NAME.sops.yml",
			path, r.keeperRecipient, r.layout.KeeperUser, r.layout.AgeKeyPath,
			path, r.layout.AgeKeyPath, r.layout.SecretsDir())
	}

	var missing []string
	for _, want := range r.opts.AgeRecipients {
		if want != r.keeperRecipient && !slices.Contains(listed, want) {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		r.warnf("--recipient named %s, and %s already exists and is kept, so "+
			"nothing was added: that key decrypts no managed value. Applying it means "+
			"re-encrypting each file, which is two steps as root:\n"+
			"  sudoedit %s\n"+
			"  sudo SOPS_AGE_KEY_FILE=%s sops updatekeys %s/NAME.sops.yml\n"+
			"Repeat the second per file; nothing walks the secrets directory.",
			strings.Join(missing, ", "), path,
			path, r.layout.AgeKeyPath, r.layout.SecretsDir())
	}

	r.step("sops config", false, fmt.Sprintf("keeping %s, %d recipient(s)", path, len(listed)))
}

// stepSSHKey mints the identity the broker lends to brokered commands, and
// asserts that it is one the broker can read.  A key opens a host only once its
// public half is in that host's authorized_keys, which this does not do.  An
// existing key at the path is adopted rather than replaced: regenerating one
// locks the broker out of every host it is already on, and adopting one is how
// --ssh-key takes a key of the operator's.
//
// Runs after stepConfig, so the file naming the key is already written, and
// before anything starts a daemon, a key the broker cannot read leaving the
// agent holding nothing.
func (r *runner) stepSSHKey() error {
	if r.opts.DryRun {
		r.reportPresence("broker ssh key", r.layout.SSHKey, "mint")
		return nil
	}
	// own=false: the directory may be the config directory, which is root's, or
	// one the operator made to hold a key of their own.  Neither is this step's to
	// take over.
	if _, err := r.fs.ensureDir(filepath.Dir(r.layout.SSHKey), 0o700,
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
	// Repaired only when this run wrote it.  A key minted by an earlier run is
	// already broker-owned and never reaches the refusal; one that is not is a key
	// the operator brought, and chowning that to the broker would take it away
	// from them rather than fix an install.
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

// checkSSHKey reports why the broker could not use the key at this path, or nil.
//
// Split out from ownSSHKey so stepPreconditions can raise the same refusal
// before any ownership is changed: this is the one thing a re-run that renames
// --broker-user stops on, and stopping on it at the SSH step left the age key
// and the audit log already handed to accounts whose units were never written.
func (r *runner) checkSSHKey(path string, uid, gid int) error {
	for _, half := range sshKeyHalves(path) {
		info, err := os.Stat(half.path)
		if err != nil {
			return fmt.Errorf("%s: %w\nThe broker needs both halves of the key. "+
				"Regenerate the public half with: ssh-keygen -y -f %s > %s",
				half.path, err, path, path+".pub")
		}
		wrong, err := wrongOwner(info, uid, gid)
		if err != nil {
			return err
		}
		if !wrong && info.Mode().Perm() == half.mode.Perm() {
			continue
		}
		// Both halves in the remedy, and the group in the chown.  This compares uid
		// and gid, so a remedy naming the owner alone leaves the same refusal
		// standing with its text now reading "X is 0600 broker2 ... so broker2
		// cannot load it": an install nothing can finish by doing as it says.
		return fmt.Errorf("%s is %s, and [ssh] key names it, so %s cannot "+
			"load it and brokered commands reach no managed host. Hand both halves "+
			"over, group as well as owner:\n"+
			"    chown %s:%s %s %s\n"+
			"    chmod 0600 %s && chmod 0644 %s\n"+
			"Or unset [ssh] key, if it is not the broker's to hold",
			half.path, ownsWithGroup(half.path), r.layout.BrokerUser,
			r.layout.BrokerUser, r.brokerGroupName(), path, path+".pub",
			path, path+".pub")
	}
	return nil
}

// ownSSHKey asserts, every run, that the broker can read both halves of the
// key: one placed by hand or left root-owned leaves the agent holding nothing,
// and nothing else says so.  A repair counts as a change.  repair is false for
// a key this run did not write, which is refused rather than taken over.
func (r *runner) ownSSHKey(path string, repair bool) (bool, error) {
	if !repair {
		return false, r.checkSSHKey(path, r.brokerUID, r.brokerGID)
	}
	changed := false
	for _, half := range sshKeyHalves(path) {
		info, err := os.Stat(half.path)
		if err != nil {
			return false, fmt.Errorf("%s: %w\nThe broker needs both halves of the key. "+
				"Regenerate the public half with: ssh-keygen -y -f %s > %s",
				half.path, err, path, path+".pub")
		}
		wrong, err := wrongOwner(info, r.brokerUID, r.brokerGID)
		if err != nil {
			return false, err
		}
		if !wrong && info.Mode().Perm() == half.mode.Perm() {
			continue
		}
		if err := os.Chown(half.path, r.brokerUID, r.brokerGID); err != nil {
			return false, err
		}
		if err := os.Chmod(half.path, half.mode); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

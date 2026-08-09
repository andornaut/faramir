package install

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/sshkey"
)

// stepAgeKey mints the keeper's identity, 0400 owned by the keeper: a key the
// broker or the executor could read is one any brokered command could read.
// The keeper takes it through systemd's LoadCredential=.
func (r *runner) stepAgeKey() error {
	// Nothing is opened under a dry run: the key is 0400 and the keeper's, so
	// the recipient is left unknown and the sops step reports it as such.
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
// store: sops resolves it from the working directory upward, so the parent is
// found from both, and the store is a glob target where filepath.Glob matches
// dotfiles.
//
// Kept if it already exists, adding or dropping a recipient meaning every
// managed value is re-encrypted.  Kept and read back -- see keepSopsConfig --
// so --age-recipient does not silently mean nothing.
func (r *runner) stepSopsConfig() error {
	path := r.layout.SopsConfigPath()
	if exists(path) {
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
	// produces a store the keeper cannot read, and a broker that serves
	// nothing.
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
	body := fmt.Sprintf(`# Which files sops encrypts, and to whom.  Any *.sops.yml, wherever it sits:
# a rule naming one layout refuses to encrypt a file kept anywhere else, and
# reports it as "no matching creation rules found".
# 'encrypted_regex' leaves keys readable and encrypts only values, so diffs
# stay per-key and reviewable.
creation_rules:
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
%s`, recipients.String())
	// Root-owned like the rest of the config directory, or the recipients could
	// be rewritten by an account the store group exists to keep out.
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
		// The file is the operator's to edit and sops is what parses it, so a
		// shape this does not understand is a question that went unasked.
		r.warn("%s could not be read (%v), so who can decrypt the store went "+
			"unchecked. sops is what has to parse this file: if it cannot either, "+
			"encrypting a new value into the store fails", path, err)
		r.step("sops config", false, "keeping "+path)
		return
	}
	// What the file says, not what was asked for: on every run but the first the
	// request had no part in it.
	r.report.AgeRecipients = listed

	// The keeper's first and separately: the others are a key that does not open
	// the store, this one is a store the keeper cannot open.  Skipped when the
	// recipient is unknown, which is reported where it happens.
	if r.keeperRecipient != "" && !slices.Contains(listed, r.keeperRecipient) {
		r.warn("%s does not list the keeper's own recipient (%s), so every value "+
			"encrypted into the store from now on is one %s cannot decrypt: the broker "+
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
		r.warn("--age-recipient named %s, and %s already exists and is kept, so "+
			"nothing was added: that key decrypts no managed value. Applying it means "+
			"re-encrypting each file, which is two steps as root:\n"+
			"  sudoedit %s\n"+
			"  sudo SOPS_AGE_KEY_FILE=%s sops updatekeys %s/NAME.sops.yml\n"+
			"Repeat the second per file; nothing walks the store.",
			strings.Join(missing, ", "), path,
			path, r.layout.AgeKeyPath, r.layout.SecretsDir())
	}

	r.step("sops config", false, fmt.Sprintf("keeping %s, %d recipient(s)", path, len(listed)))
}

// stepSSHKey generates the identity the broker lends to brokered commands.  It
// opens a host only once its public half is in that host's authorized_keys,
// which this does not do.  An existing key is left alone, regenerating one
// locking the broker out of every host it is already on.
func (r *runner) stepSSHKey() error {
	if r.opts.SSHKey == "" {
		r.skip("broker ssh key", "[ssh] keys left empty; keys must then live "+
			"somewhere the executor's own uid can read")
		return nil
	}
	if r.opts.DryRun {
		r.reportPresence("broker ssh key", r.opts.SSHKey, "generate")
		return nil
	}
	if _, err := r.fs.ensureDir(filepath.Dir(r.opts.SSHKey), 0o700,
		r.brokerUID, r.brokerGID, true); err != nil {
		return err
	}
	host, _ := os.Hostname()
	public, created, err := sshkey.Generate(r.opts.SSHKey, "faramir broker on "+host)
	if err != nil {
		return err
	}
	r.report.BrokerPublicKey = public
	// Re-asserted every run, like the age key's: a key placed by hand or left
	// root-owned is one the broker cannot read, and the only symptom is an agent
	// holding nothing.  A repair counts as a change.
	changed := created
	if !r.opts.DryRun {
		for path, mode := range map[string]os.FileMode{
			r.opts.SSHKey:          0o600,
			r.opts.SSHKey + ".pub": 0o644,
		} {
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("%s: %w\nThe broker needs both halves of the key. "+
					"Regenerate the public half with: ssh-keygen -y -f %s > %s",
					path, err, r.opts.SSHKey, r.opts.SSHKey+".pub")
			}
			wrong, err := wrongOwner(info, r.brokerUID, r.brokerGID)
			if err != nil {
				return err
			}
			if !wrong && info.Mode().Perm() == mode.Perm() {
				continue
			}
			if err := os.Chown(path, r.brokerUID, r.brokerGID); err != nil {
				return err
			}
			if err := os.Chmod(path, mode); err != nil {
				return err
			}
			changed = true
		}
	}
	if changed {
		r.restartFor("ssh key")
	}
	r.step("broker ssh key", changed, r.opts.SSHKey)
	return nil
}

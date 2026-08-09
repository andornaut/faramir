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

// stepAgeKey mints the keeper's identity.
//
// The private key ends up 0400 owned by the keeper, not the broker.  Every
// brokered command runs as the executor's uid and the broker forks them, so a
// key either of those could read is a key any command could read.  The keeper
// takes it through systemd's LoadCredential= and serves decrypted values only.
func (r *runner) stepAgeKey() error {
	// Nothing is opened under a dry run.  The key is 0400 and owned by the
	// keeper, so an unprivileged report can see that it is there and must not
	// try to read it; the recipient is left unknown, which the sops step below
	// reports rather than guesses at.
	if r.opts.DryRun {
		r.reportPresence("age key", r.layout.AgeKeyPath, "mint")
		return nil
	}
	recipient, created, err := agekey.Generate(r.layout.AgeKeyPath)
	if err != nil {
		return err
	}
	// Re-asserted every run rather than only on creation, so a key placed by
	// hand ends up owned by the keeper like a minted one.
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

// addRecipient records an age recipient for .sops.yaml, keeping the order
// stable so a re-run does not rewrite the file to say the same thing.
func (r *runner) addRecipient(recipient string) {
	if recipient == "" || slices.Contains(r.opts.AgeRecipients, recipient) {
		return
	}
	r.opts.AgeRecipients = append(r.opts.AgeRecipients, recipient)
}

// stepSopsConfig writes .sops.yaml into the config directory.
//
// There rather than in the store, for two reasons. sops resolves that file from
// the working directory upward and not from the file being encrypted, so the
// parent is found from the store as well as from the config directory, while
// the store is found only from itself. And the store is a drop zone that
// [secrets] files globs: filepath.Glob matches dotfiles, so a rule file kept
// among the ciphertext is one glob spelling away from being loaded as a managed
// file that does not decrypt, which fails the install gate and leaves the broker
// redacting nothing.
//
// Kept if it already exists: adding or dropping a recipient means re-encrypting
// every managed value, which is an operator action, not something a re-run of
// the installer should do behind their back.  Kept and read back, though -- see
// keepSopsConfig -- because keeping it in silence was how --age-recipient came to
// mean nothing at all on a host that was already installed.
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
	// A dry run does not open the age key, so the keeper's recipient is unknown
	// here for a reason of its own.  Named before the check below, which reaches
	// the same empty string by the key having been lost rather than by nothing
	// having looked, and prints a remedy that would be nonsense for this.
	if r.opts.DryRun {
		r.skip("sops config", "dry run: the keeper's recipient is not read, so what "+
			"would be written to "+path+" is not computed")
		return nil
	}
	// Never without the keeper's own recipient.  Writing the file is what decides
	// who can decrypt every value encrypted after it, and a rule listing only the
	// operator produces a store the keeper cannot read: the broker comes up, and
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
	// Root-owned like the rest of the config directory: it is edited by hand to
	// add or drop a recipient, and leaving it writable by anyone else would let
	// the recipients be rewritten by an account the store group exists to keep
	// out. World-readable because it holds public keys and a rule and no value,
	// so checking who can decrypt is not a question that should need sudo.
	changed, err := r.fs.writeFile(path, []byte(body), 0o644, 0, 0)
	if err != nil {
		return err
	}
	r.report.AgeRecipients = slices.Clone(r.opts.AgeRecipients)
	r.step("sops config", changed, fmt.Sprintf("%s, %d recipient(s)", path, len(r.opts.AgeRecipients)))
	return nil
}

// keepSopsConfig leaves an existing .sops.yaml alone and says what it says.
//
// Leaving it alone is right: applying a changed rule means re-encrypting every
// managed value, and doing that from an installer would drop a reader mid-run.
// What it cost until now was silence in both directions.  --age-recipient on an
// installed host went into the report and into nothing else, so a key an
// operator had added, and believed was a way back into the store, opened
// nothing.  And a keeper key that had been replaced -- restored from a backup,
// re-minted after the file was unlinked -- left the rule naming the recipient it
// used to have, so every value encrypted from then on was one the keeper could
// not read, and the first symptom was a broker that came up healthy and served
// nothing.
//
// So: kept, read back, and every difference between what was asked for and what
// is in the file reported.  Nothing here fails the run.  Each of these is a host
// that works today and is wrong about who can read it tomorrow, and failing the
// install would leave no way to reach the host that has to be fixed.
func (r *runner) keepSopsConfig(path string) {
	listed, err := sopsRecipients(path)
	if err != nil {
		// The file is the operator's to edit and sops is what has to parse it, so
		// a shape this does not understand is a warning about a question that went
		// unasked, not a verdict on the file.
		r.warn("%s could not be read (%v), so who can decrypt the store went "+
			"unchecked. sops is what has to parse this file: if it cannot either, "+
			"encrypting a new value into the store fails", path, err)
		r.step("sops config", false, "keeping "+path)
		return
	}
	// What the file says, not what was asked for.  This is the answer to "who can
	// decrypt the managed values", and on every run but the first the request had
	// no part in it.
	r.report.AgeRecipients = listed

	// The keeper's first, and separately: the others are a key that does not open
	// the store, this one is a store the keeper cannot open.  Skipped when the
	// recipient is unknown, which is a dry run or a key that has been removed,
	// both of which are already reported where they happen.
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

// stepSSHKey generates the identity the broker lends to brokered commands.
//
// Generating it grants nothing on its own: it opens a host only once its public
// half is in that host's authorized_keys, which is a step this does not take.
// An existing key is left alone, because regenerating one silently would lock
// the broker out of every host its public half is already on.
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
	// Re-asserted every run, not only on creation, for the same reason the age
	// key's ownership is: a key placed by hand, or left root-owned by an earlier
	// arrangement, is one the broker cannot read, and the only symptom is an
	// agent holding nothing and every brokered command reaching no host.
	//
	// A repair counts as a change.  Reporting it as no change tells a
	// configuration manager the host was already correct when this run is what
	// made it so.
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

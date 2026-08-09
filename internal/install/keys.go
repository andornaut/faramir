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
// the installer should do behind their back.
func (r *runner) stepSopsConfig() error {
	path := r.layout.SopsConfigPath()
	if exists(path) {
		r.step("sops config", false, "keeping "+path)
		return nil
	}
	if len(r.opts.AgeRecipients) == 0 {
		r.skip("sops config", "no age recipient known yet")
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
	r.step("sops config", changed, fmt.Sprintf("%s, %d recipient(s)", path, len(r.opts.AgeRecipients)))
	return nil
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

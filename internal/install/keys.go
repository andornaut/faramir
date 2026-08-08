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
	// Nothing to mint once the plaintext has deliberately been removed and the
	// keeper reads the sealed credential.  Minting here would put a brand-new
	// identity at the old path, list its recipient in the report, and leave a
	// keeper that decrypts none of the existing store: an upgrade run would turn
	// a working broker into a broken one, irreversibly, since the store is still
	// encrypted to the key that was removed.
	if exists(r.layout.AgeKeyCred) && !exists(r.layout.AgeKeyPath) {
		if !r.opts.SealAgeKey {
			return fmt.Errorf("%s is gone and %s is not, so the keeper has no key to "+
				"read. Pass --seal-age-key to keep taking it from the sealed "+
				"credential; without it this run would mint a new identity that "+
				"decrypts none of the store", r.layout.AgeKeyPath, r.layout.AgeKeyCred)
		}
		r.step("age key", false, "removed; the keeper reads "+r.layout.AgeKeyCred)
		return nil
	}
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
	r.addRecipient(recipient)
	r.step("age key", changed, fmt.Sprintf("%s, 0400 %s", r.layout.AgeKeyPath, r.layout.KeeperUser))
	return nil
}

// stepOperatorAgeKey mints an identity for the operator and lists it alongside
// the keeper's.
//
// The keeper is otherwise the only recipient, which means the account
// responsible for these secrets cannot read them: editing a value, rotating a
// credential or reading one back all have to go through the broker.
//
// Written as root and given to the operator immediately.  Left root-owned it is
// an identity the operator cannot read, listed in .sops.yaml as a recipient,
// which is the same failure as having no second recipient at all except that
// nothing reports it.
func (r *runner) stepOperatorAgeKey() error {
	if r.opts.OperatorAgeKey == "" {
		r.skip("operator age key", "not requested; the keeper stays the only recipient")
		return nil
	}
	if r.opts.DryRun {
		r.reportPresence("operator age key", r.opts.OperatorAgeKey, "mint")
		return nil
	}
	changed, err := r.fs.ensureDir(filepath.Dir(r.opts.OperatorAgeKey), 0o700,
		r.operatorUID, keep, true)
	if err != nil {
		return err
	}
	recipient, created, err := agekey.Generate(r.opts.OperatorAgeKey)
	if err != nil {
		return err
	}
	if !r.opts.DryRun {
		if err := os.Lchown(r.opts.OperatorAgeKey, r.operatorUID, keep); err != nil {
			return err
		}
	}
	r.addRecipient(recipient)
	r.step("operator age key", changed || created, r.opts.OperatorAgeKey)
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

// stepSopsConfig writes .sops.yaml beside the store.
//
// Beside it because sops resolves that file from the working directory upward,
// not from the file being encrypted, so a rule kept anywhere else is one that
// reports "no matching creation rules found" for a store edited from elsewhere.
//
// Kept if it already exists: adding or dropping a recipient means re-encrypting
// every managed value, which is an operator action, not something a re-run of
// the installer should do behind their back.
func (r *runner) stepSopsConfig() error {
	path := filepath.Join(r.layout.SecretsDir, ".sops.yaml")
	if exists(path) {
		r.step("sops config", false, "keeping "+path)
		return nil
	}
	if len(r.opts.AgeRecipients) == 0 {
		r.skip("sops config", "no age recipient known yet")
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
	// Owned by the operator, not by root: it is edited by hand to add or drop a
	// recipient, and the operator is who does that.  Group-readable because
	// encrypting reads it and the accounts that do that are not the owner.
	changed, err := r.fs.writeFile(path, []byte(body), 0o640, r.operatorUID, r.groupGID)
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
	if !r.opts.DryRun {
		for path, mode := range map[string]os.FileMode{
			r.opts.SSHKey:          0o600,
			r.opts.SSHKey + ".pub": 0o644,
		} {
			if err := os.Chown(path, r.brokerUID, r.brokerGID); err != nil {
				return err
			}
			if err := os.Chmod(path, mode); err != nil {
				return err
			}
		}
	}
	r.step("broker ssh key", created, r.opts.SSHKey)
	return nil
}

// stepSealAgeKey binds the age key to this host's TPM.
//
// Asserted rather than skipped when the host has no TPM.  A security measure
// that quietly does not apply is the install that looks healthy and protects
// less than it appears to.
//
// --name is what binds the blob: a credential decrypts only under the name it
// was encrypted with, and the keeper's unit asks for age_key.  Sealed once and
// left alone; remove the .cred to re-seal after rotating the key.
func (r *runner) stepSealAgeKey() error {
	if !r.opts.SealAgeKey {
		r.skip("seal age key", "not requested; use full-disk encryption instead, "+
			"which covers the audit log and swap as well")
		return nil
	}
	if exists(r.layout.AgeKeyCred) {
		r.step("seal age key", false, "keeping "+r.layout.AgeKeyCred)
		return nil
	}
	if r.opts.DryRun {
		r.step("seal age key", true, "seal into "+r.layout.AgeKeyCred)
		return nil
	}
	out, err := r.command("systemd-creds", "has-tpm2")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(out), "yes") {
		return fmt.Errorf("--seal-age-key was given and systemd-creds reports no usable "+
			"TPM (%s). Drop the flag and use full-disk encryption, which covers the "+
			"audit log and swap as well", strings.TrimSpace(out))
	}
	if _, err := r.command("systemd-creds", "encrypt", "--name=age_key",
		r.layout.AgeKeyPath, r.layout.AgeKeyCred); err != nil {
		return err
	}
	// Read by systemd as root at unit start, so it is never opened by the
	// keeper's own uid.
	if err := os.Chown(r.layout.AgeKeyCred, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(r.layout.AgeKeyCred, 0o400); err != nil {
		return err
	}
	r.step("seal age key", true, r.layout.AgeKeyCred)
	return nil
}

// stepRemovePlaintextAgeKey deletes the plaintext key.
//
// Last, and only after the validation step has proved the keeper is serving
// values from the sealed credential.  Until this happens the plaintext is still
// on disk and the sealing has bought nothing; after it, PCR 7 tracks Secure Boot
// policy, so changing that state stops the blob decrypting and the only way back
// is sealing the original key again.
func (r *runner) stepRemovePlaintextAgeKey() error {
	if !r.opts.RemovePlaintextAgeKey {
		if r.opts.SealAgeKey && exists(r.layout.AgeKeyPath) {
			r.warn("%s is still present, so sealing has bought nothing yet. Pass "+
				"--remove-plaintext-age-key once you have the key material somewhere "+
				"you can re-seal from", r.layout.AgeKeyPath)
		}
		r.skip("remove plaintext age key", "not requested")
		return nil
	}
	if !r.opts.SealAgeKey {
		return fmt.Errorf("--remove-plaintext-age-key without --seal-age-key would leave "+
			"the keeper with no key at all: it reads %s", r.layout.AgeKeyPath)
	}
	// The step is irreversible, so it is gated on what the validation step
	// established rather than on its own absence of complaint.  Validation skips
	// under --dry-run and on a host with no systemd, and a broker with no store
	// configured yet passes it trivially: in all three cases the sealed
	// credential has decrypted nothing, and deleting the only copy of the key
	// that can decrypt the store would be proving nothing and losing everything.
	if !r.brokerChecked || r.brokerLoadedRefs == 0 {
		return fmt.Errorf("refusing to remove %s: nothing has yet decrypted the store "+
			"from %s. The broker %s. Configure the store, re-run, and pass the flag "+
			"once the run reports refs loaded",
			r.layout.AgeKeyPath, r.layout.AgeKeyCred,
			map[bool]string{
				true:  "loaded no refs",
				false: "was never asked, because the services are not running here",
			}[r.brokerChecked])
	}
	changed, err := r.fs.remove(r.layout.AgeKeyPath)
	if err != nil {
		return err
	}
	r.step("remove plaintext age key", changed, r.layout.AgeKeyPath)
	return nil
}

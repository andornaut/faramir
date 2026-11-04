package vault

import (
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/andornaut/faramir/internal/config"
)

// AgeKeyPath is the key a run decrypts with: the install's own, beside its
// config, and no flag names another. A flag would name which key
// keeperStaysAReader checks, so a run pointed at a second identity could take
// the host's own key out of the rule and reseal the store without it, which no
// re-run undoes.
func AgeKeyPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Path), "age.key")
}

// ResealTargets is every managed file, or just the ones named, which is for a
// secrets directory where one file is meant to stay as it is. Either way a
// path that is not managed is refused by resolveManaged, so a reseal cannot
// walk out of the secrets directory.
func ResealTargets(managed, named []string) ([]string, error) {
	if len(named) == 0 {
		if len(managed) == 0 {
			return nil, ErrNoFilesToReseal
		}
		return managed, nil
	}
	out := make([]string, 0, len(named))
	for _, arg := range named {
		target, err := Resolve(managed, arg)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, target) {
			out = append(out, target)
		}
	}
	return out, nil
}

// Reencrypt rewrites one managed file, sealed to the given recipients. The
// plaintext goes through a 0600 file in a tmpfs because sops encrypts a file
// and takes its name, which is what decides its format, so the copy keeps it.
// Which creation rule governs it is settled by --filename-override; see
// sealTo.
func Reencrypt(keyPath, rulePath string, recipients []string, target string) error {
	if err := reencrypt(keyPath, rulePath, recipients, target); err != nil {
		return notWritten(err, "%s not re-encrypted", target)
	}
	return nil
}

func reencrypt(keyPath, rulePath string, recipients []string, target string) error {
	// The ciphertext as it stands now, compared again before the write: this
	// decrypts a copy of its own, and an edit that lands in between would be
	// replaced by one that never had it. See Edit.
	before, err := digestOf(target)
	if err != nil {
		return err
	}
	decrypted, err := runSops(keyPath, rulePath, "--decrypt", target)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("/dev/shm", "faramir-reseal-")
	if err != nil {
		return err
	}
	// Registered first so it runs last; see editManaged.
	defer removeOnSignal(dir)()
	defer func() { _ = os.RemoveAll(dir) }()

	plain := filepath.Join(dir, filepath.Base(target))
	if err := os.WriteFile(plain, decrypted, 0o600); err != nil {
		return err
	}
	sealed, err := sealTo(keyPath, rulePath, target, recipients, plain)
	if err != nil {
		return err
	}
	return writeBack(before, target, sealed)
}

// ErrNoFilesToReseal is a reseal over an empty store. The same words as
// errNoManagedFiles, and a separate value so a caller can tell the two apart.
var ErrNoFilesToReseal = errors.New("no managed files; create one with `faramir vault add NAME`")

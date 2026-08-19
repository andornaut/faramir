package install

import (
	"github.com/andornaut/faramir/internal/sopsrule"
)

// sopsRecipients is every age recipient .sops.yaml lists, in order, without
// repeats. Across every rule rather than the one matching the secrets:
// re-implementing sops' selection would be a second answer free to disagree
// with sops', and the question here is only whether a key is in the file at
// all.
//
// The rules themselves are read by internal/sopsrule, which is what `faramir
// reseal` re-encrypts from. One reader on purpose: a rule seals to its key
// groups alone where it carries a bare `age:` beside them, so a reader that
// merged the two would report a keeper still listed when sops is about to seal
// every new file without it.
func sopsRecipients(path string) ([]string, error) {
	rules, err := sopsrule.Load(path)
	if err != nil {
		return nil, err
	}
	return sopsrule.Recipients(rules), nil
}

// Package sopsenc encrypts a tree to age recipients the way sops does.  Shared
// by the fixture builder in internal/sopstest and the stub it builds, so a
// fixture and a re-encrypt cannot drift apart.  Test-only: nothing under cmd/
// may import it, and CI fails on a getsops hit in its deps.
package sopsenc

import (
	"fmt"
	"time"

	sops "github.com/getsops/sops/v3"
	sopsaes "github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/cmd/sops/common"
	sopsformats "github.com/getsops/sops/v3/cmd/sops/formats"
	sopsconfig "github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"
)

// Encrypt returns branches as an encrypted file in the given format, readable by
// every recipient named.  Only public recipients are needed; nothing here
// touches a private identity.
func Encrypt(format sopsformats.Format, recipients []string, branches sops.TreeBranches) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no age recipients to encrypt to")
	}
	var group sops.KeyGroup
	for _, recipient := range recipients {
		mk, err := sopsage.MasterKeyFromRecipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("recipient %s: %w", recipient, err)
		}
		group = append(group, mk)
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:         []sops.KeyGroup{group},
			Version:           version.Version,
			LastModified:      time.Now().UTC(),
			UnencryptedSuffix: sops.DefaultUnencryptedSuffix,
		},
	}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{keyservice.NewLocalClient()})
	if len(errs) > 0 {
		return nil, fmt.Errorf("generating a data key: %v", errs)
	}

	cipher := sopsaes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return nil, err
	}
	encMac, err := cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	tree.Metadata.MessageAuthenticationCode = encMac

	return common.StoreForFormat(format, sopsconfig.NewStoresConfig()).EmitEncryptedFile(tree)
}

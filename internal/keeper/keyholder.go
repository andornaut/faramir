package keeper

// Where the age key is, found once and never read.

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/andornaut/faramir/internal/config"
)

// ageSecretKeyRe matches an age identity, so one can be scrubbed from a message
// without the keeper ever reading the file.
var ageSecretKeyRe = regexp.MustCompile(`AGE-SECRET-KEY-[0-9A-Za-z]+`)

// KeyHolder locates the age key file and does not read it: sops opens it
// itself, so the material never exists in this process.
type KeyHolder struct {
	config config.KeeperConfig
	mu     sync.Mutex
	looked bool
	path   string
}

func newKeyHolder(cfg config.KeeperConfig) *KeyHolder { return &KeyHolder{config: cfg} }

// Path returns the age key file to hand sops, or "" if none is available.
func (k *KeyHolder) Path() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.looked {
		return k.path
	}
	k.looked = true

	var candidates []string
	if creds := os.Getenv("CREDENTIALS_DIRECTORY"); creds != "" && k.config.AgeKeyCredential != "" {
		candidates = append(candidates, filepath.Join(creds, k.config.AgeKeyCredential))
	}
	if k.config.AgeKeyFile != "" {
		candidates = append(candidates, k.config.AgeKeyFile)
	}
	for _, candidate := range candidates {
		// Readability, not contents.
		fh, err := os.Open(candidate)
		if err != nil {
			continue
		}
		_ = fh.Close()
		k.path = candidate
		log.Printf("age key available at %s (not read by this process)", candidate)
		return k.path
	}
	log.Printf("no age key available (tried: %s)", strings.Join(candidates, ", "))
	return ""
}

// Scrub removes key material from text, an error string being the one thing
// that crosses from this process to the broker. Matching the age identity
// format rather than a copy of the key is what lets it scrub without holding
// the material.
func (k *KeyHolder) Scrub(text string) string {
	return ageSecretKeyRe.ReplaceAllString(text, "«AGE-KEY»")
}

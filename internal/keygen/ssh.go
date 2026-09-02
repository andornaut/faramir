package keygen

// The ed25519 identity the broker lends to brokered commands.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"

	"golang.org/x/crypto/ssh"
)

// SSH writes an ed25519 keypair at path and path+".pub", returning the
// public key in authorized_keys form. created is false when the private key was
// already there and nothing is written: regenerating one would lock the broker
// out of every host its public half is on, so the file is opened O_EXCL.
func SSH(path, comment string) (public string, created bool, err error) {
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		public, err = SSHPublic(path + ".pub")
		return public, false, err
	}
	if err != nil {
		return "", false, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		_ = handle.Close()
		_ = os.Remove(path)
		return "", false, err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		_ = handle.Close()
		_ = os.Remove(path)
		return "", false, err
	}
	if _, err := handle.Write(pem.EncodeToMemory(block)); err != nil {
		_ = handle.Close()
		return "", false, err
	}
	if err := handle.Close(); err != nil {
		return "", false, err
	}
	signer, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", false, err
	}
	// The comment is what identifies the key in an authorized_keys file.
	line := string(ssh.MarshalAuthorizedKey(signer))
	line = line[:len(line)-1] + " " + comment + "\n"
	// 0644: the public half is copied into authorized_keys on every managed
	// host.
	if err := os.WriteFile(path+".pub", []byte(line), 0o644); err != nil { //nolint:gosec
		return "", false, err
	}
	return line[:len(line)-1], true, nil
}

// SSHPublic reads an authorized_keys line back from a .pub file.
func SSHPublic(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return "", err
	}
	line := string(ssh.MarshalAuthorizedKey(key))
	line = line[:len(line)-1]
	if comment != "" {
		line += " " + comment
	}
	return line, nil
}

// Uses the local GPG key store.
package local

import (
	"bytes"
	"errors"
	"os/exec"

	"camlistore.org/pkg/misc/pinentry"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func Unlock(username, _ string) (openpgp.EntityList, error) {
	// Request the password only once as it will be used both to export the
	// private key and to decrypt it
	req := &pinentry.Request{
		Desc: "Please enter the passphrase for your main PGP key.",
	}

	passphrase, err := req.GetPIN()
	if err != nil {
		return nil, err
	}

	// Export private key
	cmd := exec.Command("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", passphrase, "--export-secret-keys")

	b := &bytes.Buffer{}
	cmd.Stdout = b

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	if b.Len() == 0 {
		return nil, errors.New("cannot find any local private key")
	}

	kr, err := openpgp.ReadKeyRing(b)
	if err != nil {
		return nil, err
	}

	// Build a list of keys to decrypt
	var keys []*packet.PrivateKey
	for _, e := range kr {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil {
			keys = append(keys, e.PrivateKey)
		}

		// Entity.Subkeys can be used for encryption
		for _, subKey := range e.Subkeys {
			if subKey.PrivateKey != nil {
				keys = append(keys, subKey.PrivateKey)
			}
		}
	}

	// Decrypt all private keys
	for _, key := range keys {
		if !key.Encrypted {
			continue // Key already decrypted
		}

		if err = key.Decrypt([]byte(passphrase)); err != nil {
			return nil, err
		}
	}

	return kr, nil
}

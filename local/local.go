// Uses the local GPG key store.
package local

import (
	"bytes"
	"errors"
	"os/exec"

	"golang.org/x/crypto/openpgp"
)

func Unlock(username, _ string) (openpgp.KeyRing, error) {
	cmd := exec.Command("gpg", "--export-secret-keys")

	b := &bytes.Buffer{}
	cmd.Stdout = b

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	if b.Len() == 0 {
		return nil, errors.New("cannot find any local private key")
	}

	return openpgp.ReadKeyRing(b)
}

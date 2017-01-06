package imap

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"

	"github.com/emersion/go-pgpmail/pgpmail"
)

func decryptMessage(kr openpgp.KeyRing, r io.Reader) (io.Reader, error) {
	b := new(bytes.Buffer)
	if err := pgpmail.Decrypt(b, r, kr); err != nil {
		return nil, err
	}
	return b, nil
}

func encryptMessage(kr openpgp.EntityList, w io.Writer, r io.Reader) error {
	return pgpmail.Encrypt(w, r, kr, kr[0])
}

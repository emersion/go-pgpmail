package imap

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"
	"github.com/emersion/go-message"

	"github.com/emersion/go-pgpmail/pgpmessage"
)

func decryptMessage(kr openpgp.KeyRing, r io.Reader) (io.Reader, error) {
	e, err := message.Read(r)
	if err != nil {
		return nil, err
	}

	e, err = pgpmessage.DecryptEntity(e, kr)
	if err != nil {
		return nil, err
	}

	// TODO: do not use a buffer here
	b := new(bytes.Buffer)
	if err := e.WriteTo(b); err != nil {
		return nil, err
	}
	return b, nil
}

func encryptMessage(kr openpgp.EntityList, w io.Writer, r io.Reader) error {
	return pgpmessage.Encrypt(w, r, kr, kr[0])
}

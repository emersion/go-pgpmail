package pgp

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"

	"github.com/emersion/go-imap-pgp/message"
	"github.com/emersion/go-imap-pgp/pgpmessage"
)

func decryptMessage(kr openpgp.KeyRing, r io.Reader) (io.Reader, error) {
	p, err := message.ReadPart(r)
	if err != nil {
		return nil, err
	}

	p, err = pgpmessage.DecryptPart(p, kr)
	if err != nil {
		return nil, err
	}

	b := bytes.Buffer{}
	message.CreatePart(&b, p.Header)

	return io.MultiReader(&b, p), nil
}

func encryptMessage(kr openpgp.EntityList, w io.Writer, r io.Reader) error {
	p, err := message.ReadPart(r)
	if err != nil {
		return err
	}

	if err := pgpmessage.EncryptPart(w, p, kr, kr[0]); err != nil {
		return err
	}

	return nil
}

package imap

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"

	"github.com/emersion/go-pgpmail/message"
	"github.com/emersion/go-pgpmail/pgpmessage"
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

	b := &bytes.Buffer{}
	mw, err := message.CreateWriter(b, p.Header)
	if err != nil {
		return nil, err
	}
	defer mw.Close()

	if _, err := io.Copy(mw, p); err != nil {
		return nil, err
	}

	return b, nil
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

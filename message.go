package pgp

import (
	"bytes"
	"io"
	"net/mail"
	"net/textproto"

	"github.com/emersion/go-imap-pgp/openpgp"
)

func decryptMessage(kr openpgp.KeyRing, r io.Reader) (io.Reader, error) {
	m, err := mail.ReadMessage(r)
	if err != nil {
		return nil, err
	}

	m, err = openpgp.DecryptMessage(kr, m)
	if err != nil {
		return nil, err
	}

	b := bytes.Buffer{}
	writeHeader(&b, textproto.MIMEHeader(m.Header))

	return io.MultiReader(&b, m.Body), nil
}

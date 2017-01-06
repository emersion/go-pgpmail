package pgpmail

import (
	"io"

	"golang.org/x/crypto/openpgp"
)

func decrypt(r io.Reader, kr openpgp.KeyRing) (*openpgp.MessageDetails, error) {
	return openpgp.ReadMessage(r, kr, nil, nil)
}

func encrypt(w io.Writer, to []*openpgp.Entity, signed *openpgp.Entity) (io.WriteCloser, error) {
	return openpgp.Encrypt(w, to, signed, nil, nil)
}

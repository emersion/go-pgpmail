package pgpmessage

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// Armored type for PGP encrypted messages.
const pgpMessageType = "PGP MESSAGE"

var armorTag = []byte("-----BEGIN "+pgpMessageType+"-----")

func decryptArmored(in io.Reader, kr openpgp.KeyRing) (*openpgp.MessageDetails, error) {
	// TODO: check newline after armorTag
	b := make([]byte, len(armorTag))
	if _, err := io.ReadAtLeast(in, b, len(b)); err != nil {
		// TODO: handle io.EOF here
		return nil, err
	}

	in = io.MultiReader(bytes.NewReader(b), in)
	if !bytes.Equal(b, armorTag) {
		// Not encrypted
		return &openpgp.MessageDetails{UnverifiedBody: in}, nil
	}

	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	md, err := decrypt(block.Body, kr)
	if err != nil {
		return nil, err
	}

	return md, nil
}

// An io.WriteCloser that both encrypts and armors data.
type armorEncryptWriter struct {
	aw io.WriteCloser // Armored writer
	ew io.WriteCloser // Encrypted writer
}

func (w *armorEncryptWriter) Write(b []byte) (n int, err error) {
	return w.ew.Write(b)
}

func (w *armorEncryptWriter) Close() (err error) {
	if err = w.ew.Close(); err != nil {
		return
	}
	err = w.aw.Close()
	return
}

func encryptArmored(out io.Writer, to []*openpgp.Entity, signed *openpgp.Entity) (io.WriteCloser, error) {
	aw, err := armor.Encode(out, pgpMessageType, nil)
	if err != nil {
		return nil, err
	}

	ew, err := encrypt(aw, to, signed)
	if err != nil {
		return nil, err
	}

	return &armorEncryptWriter{aw: aw, ew: ew}, err
}

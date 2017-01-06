package pgpmessage

import (
	"bufio"
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// Armored type for PGP encrypted messages.
const pgpMessageType = "PGP MESSAGE"

var armorTag = []byte("-----BEGIN "+pgpMessageType+"-----")

func decryptArmored(in io.Reader, kr openpgp.KeyRing) (*openpgp.MessageDetails, error) {
	br := bufio.NewReaderSize(in, len(armorTag))

	// Read all empty lines at the begining
	var line []byte
	var isPrefix bool
	for len(line) == 0 {
		var err error
		line, isPrefix, err = br.ReadLine()
		if err != nil {
			return nil, err
		}

		line = bytes.TrimSpace(line)
	}

	// bufio.Reader doesn't consume the newline after the armor tag
	in = io.MultiReader(bytes.NewReader(line), in)
	if !isPrefix || !bytes.Equal(line, armorTag) {
		// Not encrypted
		return &openpgp.MessageDetails{UnverifiedBody: in}, nil
	}

	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	return decrypt(block.Body, kr)
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

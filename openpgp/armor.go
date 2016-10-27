package openpgp

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var armorTag = []byte("-----BEGIN PGP MESSAGE-----")

func decryptArmored(kr openpgp.KeyRing, in io.Reader) (io.Reader, error) {
	// TODO: check newline after armorTag
	b := make([]byte, len(armorTag))
	if _, err := io.ReadAtLeast(in, b, len(b)); err != nil {
		// TODO: handle io.EOF here
		return nil, err
	}

	in = io.MultiReader(bytes.NewReader(b), in)
	if !bytes.Equal(b, armorTag) {
		// Not encrypted
		return in, nil
	}

	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	md, err := openpgp.ReadMessage(block.Body, kr, nil, nil)
	if err != nil {
		return nil, err
	}

	return md.UnverifiedBody, nil
}

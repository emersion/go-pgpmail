package pgpmail

import (
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

var testPrivateKey = mustReadArmoredEntity(testPrivateKeyArmored)
var testPublicKey = mustReadArmoredEntity(testPublicKeyArmored)

var testConfig = &packet.Config{
	Rand: &zeroReader{},
	Time: func() time.Time {
		return time.Date(2020, 2, 20, 0, 0, 0, 0, time.UTC)
	},
}

func mustReadArmoredEntity(s string) *openpgp.Entity {
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(s))
	if err != nil {
		panic(fmt.Errorf("pgpmail: failed to read test key: %v", err))
	}
	if len(el) != 1 {
		panic("pgpmail: test keyring doesn't contain exactly one key")
	}
	return el[0]
}

func toCRLF(s string) string {
	return strings.ReplaceAll(s, "\n", "\r\n")
}

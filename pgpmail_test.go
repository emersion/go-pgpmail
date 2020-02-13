package pgpmail

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var testPrivateKey, testPublicKey *openpgp.Entity

var testConfig = &packet.Config{
	Rand: rand.New(rand.NewSource(42)),
	Time: func() time.Time {
		return time.Date(2020, 2, 13, 0, 0, 0, 0, time.UTC)
	},
}

func init() {
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(testPrivateKeyArmored))
	if err != nil {
		panic(fmt.Errorf("pgpmail: failed to read test private key: %v", err))
	}
	if len(el) != 1 {
		panic("pgpmail: test private keyring doesn't contain exactly one key")
	}
	testPrivateKey = el[0]

	el, err = openpgp.ReadArmoredKeyRing(strings.NewReader(testPublicKeyArmored))
	if err != nil {
		panic(fmt.Errorf("pgpmail: failed to read test public key: %v", err))
	}
	if len(el) != 1 {
		panic("pgpmail: test public keyring doesn't contain exactly one key")
	}
	testPublicKey = el[0]
}

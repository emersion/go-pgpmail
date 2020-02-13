package pgpmail

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var testPrivateKey = mustReadArmoredEntity(testPrivateKeyArmored)
var testPublicKey = mustReadArmoredEntity(testPublicKeyArmored)

var testConfig = &packet.Config{
	Rand: rand.New(rand.NewSource(42)),
	Time: func() time.Time {
		return time.Date(2020, 2, 13, 0, 0, 0, 0, time.UTC)
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

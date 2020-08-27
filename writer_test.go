package pgpmail

import (
	"bytes"
	"io"
	"testing"

	"github.com/emersion/go-message/textproto"
	"golang.org/x/crypto/openpgp"
)

func init() {
	forceBoundary = "foo"
}

var wantEncrypted = toCRLF(`Content-Type: multipart/encrypted; boundary=foo;
 protocol="application/pgp-encrypted"
To: John Doe <john.doe@example.org>
From: John Doe <john.doe@example.org>

--foo
Content-Type: application/pgp-encrypted

Version: 1

--foo
Content-Type: application/octet-stream

-----BEGIN PGP MESSAGE-----

wcBMAxF0jxulHQ8+AQgAMKEqgZA3ZR6K79wGFa67rAxC9NudHUXFaXKAxOZqKmt9
dSH+jIbVrnM/5+/noaHY+3/YbPcow/E0XIfb/G0TDfLI1y5NyLRN5u8ms293ONqL
xbEBp1f/mert3UTvi3ewCd4V/bP7+s2XcwgpRFZE6wYV+iFHS1IgMdqNHR2lNhNW
wszcVy6rRCdhiYsgz56YASPfJmGroPARzh1LIPoTKwXisLnAaM0JUb6f2E2/K2Jp
Z6OMrPfiGPl/XGhr80B9UaQjSkMZx8cH3L7Av3Q+q7llRmBK2Y5Skgl96RDDX0Pr
x/6tBxa96LXINovCGS/BZ1jbv9xL175G7x4iXH9VYNLoAWbpS9Tviiw7iEz6Wco0
Ky73lXlHUeKW1iOhBjsdHiTYWjWxjUI4/xVuLtZR+kPSFwtWk6l2bXFIkXfLWEZa
GaWNUw9QDq0lmzPYjllf7w1xyzhVvy1lDYfTEqkQb2dRgq1RDiGIHv+m9Py/VCRs
PGclDkgSntUG1EEgm368uZuf2b8WNxd5ETQwN51GwG4j/fXDlFLbaalmMuHHnFJH
5tmqyHpcj+YezgVJyf99p7G6POKngvw6ksXWZ9snYm4Zgf+i+JcmRBksKDuHKcYS
9/uUm+B9mc1Omacqlhk5mZLEja0z0CFx2/g6m3U58BqnInTOt/8wj7awi6kbZklI
4eexCs1vVwC4JV8t5j0Ov0aWCzHxwG9NT5IaztBF5IN/rP7A+YL7z9tRAhZi9Y+v
5j5d2tu1N4MNiAMo0zQD8ZrEYp2NPW1gtQfncZ/2OADe2AsIoIC9O5CQx/ArNaGS
uX9lm1jXaMF9uWaMbZS4nUMSxYUPUH3m3jF+EprSA0KEn+QMdXQ7uIQJEDYXZbCL
2DR946rucf3cLHcq4vPRbdrhEvkA
=ZZaX
-----END PGP MESSAGE-----
--foo--
`)

var wantSigned = toCRLF(`Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha256;
 protocol="application/pgp-signature"
To: John Doe <john.doe@example.org>
From: John Doe <john.doe@example.org>

--foo
Content-Type: text/plain

This is a signed message!
--foo
Content-Type: application/pgp-signature

-----BEGIN PGP MESSAGE-----

wsBcBAABCAAQBQJeRJGACRAwchXBPfepZAAA5Z4IADF132czF1jgelC07XfICiE9
Vs1Y4x8G1ATwMOBiJGksIiPM0FoYRUat88bgSC0H/vX3pCC8vVR+1VFBAvN0oTit
33k+/VAgs0bKJ+Aufc89Dw/aKaJc6YTXGtDMpVZO5i4PchM+FEVoFaIdxRXBwB7s
3eIMgIC+E4J9Z3s70guKYnnB0EOBNZm60XO6asYpwLr+48tzUaEC3fn150jP8Oog
ZZ6/CRPeITuImRrbZEOiH1ASwm92MGWbLEh3fR78UoIgWty5hDyO65JDoKrER2oE
3Nm4liaIoOqCMq8bD6e/ntm0ZaPQPV0Ij4jswXJ6aZevSpYZOkTxXA9smL+lhjc=
=HHGH
-----END PGP MESSAGE-----
--foo--
`)

func TestEncrypt(t *testing.T) {
	var h textproto.Header
	h.Set("From", "John Doe <john.doe@example.org>")
	h.Set("To", "John Doe <john.doe@example.org>")

	var encryptedHeader textproto.Header
	encryptedHeader.Set("Content-Type", "text/plain")

	var encryptedBody = "This is an encrypted message!"

	to := []*openpgp.Entity{testPublicKey}

	var buf bytes.Buffer
	cleartext, err := Encrypt(&buf, h, to, testPrivateKey, testConfig)
	if err != nil {
		t.Fatalf("Encrypt() = %v", err)
	}

	if err := textproto.WriteHeader(cleartext, encryptedHeader); err != nil {
		t.Fatalf("textproto.WriteHeader() = %v", err)
	}
	if _, err := io.WriteString(cleartext, encryptedBody); err != nil {
		t.Fatalf("io.WriteString() = %v", err)
	}

	if err := cleartext.Close(); err != nil {
		t.Fatalf("ciphertext.Close() = %v", err)
	}

	if s := buf.String(); s != wantEncrypted {
		t.Errorf("Encrypt() = \n%v\n but want \n%v", s, wantEncrypted)
	}
}

func TestSign(t *testing.T) {
	var h textproto.Header
	h.Set("From", "John Doe <john.doe@example.org>")
	h.Set("To", "John Doe <john.doe@example.org>")

	var signedHeader textproto.Header
	signedHeader.Set("Content-Type", "text/plain")

	var signedBody = "This is a signed message!"

	var buf bytes.Buffer
	cleartext, err := Sign(&buf, h, signedHeader, testPrivateKey, testConfig)
	if err != nil {
		t.Fatalf("Encrypt() = %v", err)
	}

	if _, err := io.WriteString(cleartext, signedBody); err != nil {
		t.Fatalf("io.WriteString() = %v", err)
	}

	if err := cleartext.Close(); err != nil {
		t.Fatalf("ciphertext.Close() = %v", err)
	}

	if s := buf.String(); s != wantSigned {
		t.Errorf("Encrypt() = \n%q\n but want \n%q", s, wantSigned)
	}
}

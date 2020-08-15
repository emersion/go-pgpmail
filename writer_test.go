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

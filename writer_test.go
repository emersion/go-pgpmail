package pgpmail

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/emersion/go-message/textproto"
	"golang.org/x/crypto/openpgp"
)

func init() {
	forceBoundary = "foo"
}

var wantEncrypted = strings.ReplaceAll(`Content-Type: multipart/encrypted; boundary=foo;
 protocol="application/pgp-encrypted"
To: John Doe <john.doe@example.org>
From: John Doe <john.doe@example.org>

--foo
Content-Type: application/pgp-encrypted

Version: 1

--foo
Content-Type: application/octet-stream

-----BEGIN PGP MESSAGE-----

wcBMAxF0jxulHQ8+AQgAWezllQtm+CSyURcujyHC3bX7PkkhjSj0OHIleBgaeokO
Fvl6FrOt/tWWll6hmeIRqG0w+9RHqELc6uIxRX4Z0kEE8mBVQm14XbD1pF89UcUm
Dr+7aFN41qxITyfgpueVKK8NUdRqwEo+hCZuglWJvrP8886URjTGwZXZK8igAWPK
nmh9Y9fh2gQu1uh8KS+xa1WmsP5k5rnVgxCalY8GKdQgxb+M4M53g/MsTZiax4zB
LNXAtucrImDrgX3tbIg3DJMlJ6/OQOzxrTIz+kAsPYGYRAQmYn8Vl+7+MlwCAFGa
2oL+hE3UvLzIcBKgLSrMPrHrW9AFqSCrZq3DS8n00tLgAeSLN8xZwb2Sx0IfQTK8
Ov5C4crK4VN24+xe7AmNjvVn4gBISH3g4+AQ4MDhTNvgZ+IcsPyF4DLk5hS8mQLm
aE9LD8sQmC6kxuBY42mTL8KEwV3o4MbhZtfgcOGDk+DB5HAWJTIXDlJQDPtMex5M
RgPgjuOZnM9BWf8L2uCo4kD12hDgR+DU4IDhgMvg2uQGpFM3OxTxRhoYkASx2RIt
4mHv4N/hnuPh9EPhnSjhb4joHJW0sFglMOqObXajFbKTrwUafDRbjaEQrCSX1d3l
Gm6Z7B52z/3EAVeQhAnkPDy6AeDk6y7+1S5PK6BCe1xrmVGvnXew0oAOLbiVGpWK
KzUMM1d2bOkdqECHEBKud1j1/dpn4fEz6WfM2w9lPl0hqgs/eMe0gtDA8rzAac+u
uBGs+2cD3PE9eCHwuP6uUkh4ghNXvHrqZXlPPfkUXgpax3l9LwQUJvExcfHzoj14
AGZcCp4vLtfeEptARBIotvcLMAxUhE7B8k5kW731EPex7vglmvqZeQVOTduxtY8w
HOeQ5sDIkcuxainHiFQXGJgt6UXADLSWo/8qNX9QwNN9TuRo013UV/MVJlJdfm29
ZULA4lZzQyjhfWYA
=fWkt
-----END PGP MESSAGE-----
--foo--
`, "\n", "\r\n")

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

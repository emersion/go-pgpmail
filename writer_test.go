package pgpmail

import (
	"bytes"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-message/textproto"
)

func init() {
	forceBoundary = "foo"
}

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
	cleartext, err := Sign(&buf, h, testPrivateKey, testConfig)
	if err != nil {
		t.Fatalf("Encrypt() = %v", err)
	}

	if err := textproto.WriteHeader(cleartext, signedHeader); err != nil {
		t.Fatalf("textproto.WriteHeader() = %v", err)
	}
	if _, err := io.WriteString(cleartext, signedBody); err != nil {
		t.Fatalf("io.WriteString() = %v", err)
	}

	if err := cleartext.Close(); err != nil {
		t.Fatalf("ciphertext.Close() = %v", err)
	}

	if s := buf.String(); s != wantSigned {
		t.Errorf("Encrypt() = \n%v\n but want \n%v", s, wantSigned)
	}
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

wcBMAxF0jxulHQ8+AQf+MKEqgZA3ZR6K79wGFa67rAxC9NudHUXFaXKAxOZqKmt9
dSH+jIbVrnM/5+/noaHY+3/YbPcow/E0XIfb/G0TDfLI1y5NyLRN5u8ms293ONqL
xbEBp1f/mert3UTvi3ewCd4V/bP7+s2XcwgpRFZE6wYV+iFHS1IgMdqNHR2lNhNW
wszcVy6rRCdhiYsgz56YASPfJmGroPARzh1LIPoTKwXisLnAaM0JUb6f2E2/K2Jp
Z6OMrPfiGPl/XGhr80B9UaQjSkMZx8cH3L7Av3Q+q7llRmBK2Y5Skgl96RDDX0Pr
x/6tBxa96LXINovCGS/BZ1jbv9xL175G7x4iXH9VYNLA7wFm6UvU74osO4hM+lnK
NCsu95V5R1HjltYjoQY7HR4k2KplLD7fqWrm/dj8IrwqSrSa6ZgHZCEpROx/goiQ
oqyhtF3XXohwM0C6Mr+ojdmXbBNdOmv3sm+isdFGCIGgiYhcAyBRDMehx3sBLWLY
8oeqR759MhzKztHC0sZa08OMeIpCEINy4eDEAQdbWDg1l+J9W9Bqd5vqx9FI82np
FMueiumFwi+zjV17M/taOLeLGVJudwsH9eWcX2NdyHvTfNWRfx20Z50GB0nwkb9n
4vTfow0vXbcT+1ajnOyrOljwBGfgvcpBG1/9WEQxMoA5tvH3i7y9T4SxpJ2+DjqG
dxGdo+sj0PiQObhCj3sHVIoRHYSCLWid78VY8GUZrBdBA6NAlxj6Pk36Lkp66/55
JaJo2G7ZVnezLkPlr9gFbdc4kkel5ABAD8/1zLIG4LcrCHBBgH5lIP7uv+dAwtsE
jQfrJzA1FD4ZRprc7qhbcIq6NRBIj8amu/KHvBBi+zNOUW4QtrC23LHOGYldrcu1
o3q42OYigPcRIYlmmqkyBmj16Kj5jPnjDry9iv68Z6ot
=TtuG
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

wsBzBAEBCAAnBQJeTcwACZAwchXBPfepZBahBLGoZpNUFTt5nyIXvzByFcE996lk
AACmXQgAiu/yJb2o3AX/GYt/GUSEWkYb1GI41ogLpoicrX6UPoUhuIwzNQHvSG62
DDsMrNBKUZfymp6iYFRBEs9Au0o8WwqMFGWWgaDxvI2144gSDN4CDKtyCVRGNcIf
PeL+vfpZIEV1JzzRKLl3nGlFbnSTfpxUg3EYNy51RHNmbvJGRzi43CTYJUp7Lh+/
ibogULsL0ZH3M6QtGhUNcujjqUmVAvAqVxwf7BjBta/G2hOPPCQeVjFsOgcWuIQr
GudsXpoK1FQ+NUrGcXJGgV+bq6r9IGEUafjGJ3087q9hz5drBoUgqlyl62wn7krB
Ql3Afgbl74/eTZO7Mr5cx3us80F3AQ==
=6GTz
-----END PGP MESSAGE-----
--foo--
`)

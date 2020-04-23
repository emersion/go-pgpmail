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
x/6tBxa96LXINovCGS/BZ1jbv9xL175G7x4iXH9VYNLgAeRm6UvU74osO4hM+lnK
NCsu4feV4XlH41HiltYjoQY74h0eJNjgWuA14LXhjULg2uL/FW5t4F3kfOFIyAZ0
8R3ciiuFij5MsOAx47PqVVVmS4RD4C3h9z3giOFV+eDH5Nsg1tX5GqDdK9Jy/itA
kdfgreMJ0aXJW8nXdOD/4qBr167gkeDr4F/hx9vg5OQVbHyPUiwxcHWpOsLSGkQr
4hU37XrhJDbh7vrh/u7h3TLoOwnnQyQlJsNqUIMetIffdLDqTmUGd4JsvOcH98Ak
hLsbNpQjjnnCIYdtpNVpxxjKwP53xfxm1iktUYfbkdlrxmQDK/XyuYVbfJPyg2CC
YisvCMJ4VuuOI/wZ/YCxKb+6Ct45TtQUHwHxFxrz5F9p8BJQbT9pxhQVxeLh8+xc
M5lazmLGboCla1vGa74AsBmF0cQiJ4YmaYI++NddoEfmNuMvuu/9Ov2eaAu5iApz
CsJMFUmRh8sRTBjDv0nzVGegnNwbaAmm2AEoYfEm54KVvMeFYp9WUs8y1HQLS9jY
BIC6gLJy2TZjt6SlOUbWEqGJ8iwKgvc8kWQs4w5xFP1p0OSR4yg359+1q8p27mFv
kx/p4lCUZ43hdjMA
=EZSF
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

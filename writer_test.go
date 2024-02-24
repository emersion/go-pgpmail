package pgpmail

import (
	"bytes"
	"io"
	"io/ioutil"
	"strings"
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

	s := buf.String()
	if !strings.HasPrefix(s, wantEncryptedPrefix) || !strings.HasSuffix(s, wantEncryptedSuffix) {
		t.Errorf("Encrypt() has invalid structure:\n%v", s)
	}

	r, err := Read(&buf, openpgp.EntityList{testPrivateKey}, nil, nil)
	if err != nil {
		t.Fatalf("Read() = %v", err)
	}
	b, err := ioutil.ReadAll(r.MessageDetails.UnverifiedBody)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	checkSignature(t, r.MessageDetails)
	checkEncryption(t, r.MessageDetails)
	encryptedMessage := formatMessage(encryptedHeader, encryptedBody)
	if s := string(b); s != encryptedMessage {
		t.Errorf("MessagesDetails.UnverifiedBody = \n%v\n but want \n%v", s, encryptedMessage)
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
		t.Fatalf("Sign() = %v", err)
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

	s := buf.String()
	if !strings.HasPrefix(s, wantSignedPrefix) || !strings.HasSuffix(s, wantSignedSuffix) {
		t.Errorf("Sign() has invalid structure:\n%v", s)
	}

	r, err := Read(&buf, openpgp.EntityList{testPrivateKey}, nil, nil)
	if err != nil {
		t.Fatalf("Read() = %v", err)
	}
	b, err := ioutil.ReadAll(r.MessageDetails.UnverifiedBody)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	checkSignature(t, r.MessageDetails)
	signedMessage := formatMessage(signedHeader, signedBody)
	if s := string(b); s != signedMessage {
		t.Errorf("MessagesDetails.UnverifiedBody = \n%v\n but want \n%v", s, signedMessage)
	}
}

func formatMessage(h textproto.Header, body string) string {
	var sb strings.Builder
	textproto.WriteHeader(&sb, h)
	sb.WriteString(body)
	return sb.String()
}

var wantEncryptedPrefix = toCRLF(`Mime-Version: 1.0
Content-Type: multipart/encrypted; boundary=foo;
 protocol="application/pgp-encrypted"
To: John Doe <john.doe@example.org>
From: John Doe <john.doe@example.org>

--foo
Content-Type: application/pgp-encrypted

Version: 1

--foo
Content-Type: application/octet-stream

-----BEGIN PGP MESSAGE-----
`)

var wantEncryptedSuffix = toCRLF(`
-----END PGP MESSAGE-----
--foo--
`)

var wantSignedPrefix = toCRLF(`Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha256;
 protocol="application/pgp-signature"
To: John Doe <john.doe@example.org>
From: John Doe <john.doe@example.org>

--foo
Content-Type: text/plain

This is a signed message!
--foo
Content-Type: application/pgp-signature

-----BEGIN PGP MESSAGE-----
`)

var wantSignedSuffix = toCRLF(`
-----END PGP MESSAGE-----
--foo--
`)

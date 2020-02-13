package pgpmail

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func checkSignature(t *testing.T, md *openpgp.MessageDetails) {
	primaryKeyId := testPrivateKey.PrimaryKey.KeyId
	if md.SignatureError != nil {
		t.Errorf("MessageDetails.SignatureError = %v", md.SignatureError)
	}
	if !md.IsSigned {
		t.Errorf("MessageDetails.IsSigned != true")
	}
	if md.SignedByKeyId != primaryKeyId {
		t.Errorf("MessageDetails.SignedByKeyId = %v, want %v", md.SignedByKeyId, primaryKeyId)
	}
}

func TestReader_encryptedPGPMIME(t *testing.T) {
	sr := strings.NewReader(testPGPMIMEEncrypted)
	r, err := Read(sr, openpgp.EntityList{testPrivateKey}, nil, nil)
	if err != nil {
		t.Fatalf("pgpmail.Read() = %v", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r.MessageDetails.UnverifiedBody); err != nil {
		t.Fatalf("io.Copy() = %v", err)
	}

	encryptedTo := testPrivateKey.Subkeys[0].PublicKey.KeyId
	if !r.MessageDetails.IsEncrypted {
		t.Errorf("MessageDetails.IsEncrypted != true")
	}
	if len(r.MessageDetails.EncryptedToKeyIds) != 1 {
		t.Errorf("MessageDetails.EncryptedToKeyIds = %v, want exactly one key", r.MessageDetails.EncryptedToKeyIds)
	} else if r.MessageDetails.EncryptedToKeyIds[0] != encryptedTo {
		t.Errorf("MessageDetails.EncryptedToKeyIds = %v, want key %v", r.MessageDetails.EncryptedToKeyIds, encryptedTo)
	}
	checkSignature(t, r.MessageDetails)

	if s := buf.String(); s != testEncryptedBody {
		t.Errorf("MessagesDetails.UnverifiedBody = \n%v\n but want \n%v", s, testEncryptedBody)
	}
}

func TestReader_signedPGPMIME(t *testing.T) {
	sr := strings.NewReader(testPGPMIMESigned)
	r, err := Read(sr, openpgp.EntityList{testPrivateKey}, nil, nil)
	if err != nil {
		t.Fatalf("pgpmail.Read() = %v", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r.MessageDetails.UnverifiedBody); err != nil {
		t.Fatalf("io.Copy() = %v", err)
	}

	if r.MessageDetails.IsEncrypted {
		t.Errorf("MessageDetails.IsEncrypted != false")
	}
	checkSignature(t, r.MessageDetails)

	if s := buf.String(); s != testSignedBody {
		t.Errorf("MessagesDetails.UnverifiedBody = \n%v\n but want \n%v", s, testSignedBody)
	}
}

func TestReader_plaintext(t *testing.T) {
	sr := strings.NewReader(testPlaintext)
	r, err := Read(sr, openpgp.EntityList(nil), nil, nil)
	if err != nil {
		t.Fatalf("pgpmail.Read() = %v", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r.MessageDetails.UnverifiedBody); err != nil {
		t.Fatalf("io.Copy() = %v", err)
	}

	if r.MessageDetails.IsEncrypted {
		t.Errorf("MessageDetails.IsEncrypted != false")
	}
	if r.MessageDetails.IsSigned {
		t.Errorf("MessageDetails.IsSigned != false")
	}

	if s := buf.String(); s != testPlaintext {
		t.Errorf("MessagesDetails.UnverifiedBody = \n%v\n but want \n%v", s, testPlaintext)
	}
}

var testEncryptedBody = toCRLF(`Content-Type: text/plain

This is an encrypted message!
`)

var testSignedBody = toCRLF(`Content-Type: text/plain

This is a signed message!
`)

var testPGPMIMEEncrypted = toCRLF(`From: John Doe <john.doe@example.org>
To: John Doe <john.doe@example.org>
Mime-Version: 1.0
Content-Type: multipart/encrypted; boundary=foo;
   protocol="application/pgp-encrypted"

--foo
Content-Type: application/pgp-encrypted

Version: 1

--foo
Content-Type: application/octet-stream

-----BEGIN PGP MESSAGE-----

hQEMAxF0jxulHQ8+AQf/SBK2FIIgMA4OkCvlqty/1GmAumWq6J0T+pRLppXHvYFb
jbXRzz2h3pE/OoouI6vWzBwb8xU/5f8neen+fvdsF1N6PyLjZcHRB91oPvP8TuHA
0vEpiQDbP+0wlQ8BmMnnV06HokWJoKXGmIle0L4QszT/QCbrT80UgKrqXNVHKQtN
DUcytFsUCmolZRj074FEpEetjH6QGEX5hAYNBUJziXmOv7vdd4AFgNbbgC5j5ezz
h8tCAKUqeUiproYaAMrI0lfqh/t8bacJNkljI2LOxYfdJ/2317Npwly0OqpCM3YT
Q4dHuuGM6IuZHtIc9sneIBRhKf8WnWt14hLkHUT80dLA/AHKl0jGYqO34Dxd9JNB
EEwQ4j6rxauOEbKLAuYYaEqCzNYBasBrPmpNb4Fx2syWkCoYzwvzv7nj4I8vIBmm
FGsAQLX4c18qtZI4XaG4FPUvFQ01Y0rjTxAV3u51lrYjCxFuI5ZEtiT0J/Tv2Unw
R6xwtARkEf3W0agegmohEjjkAexKNxGrlulLiPk2j9/dnlAxeGpOuhYuYU2kYbKq
x3TkcVYRs1FkmCX0YHNJ2zVWLfDYd2f3UVkXINe7mODGx2A2BxvK9Ig7NMuNmWZE
ELiLSIvQk9jlgqWUMwSGPQKaHPrac02EjcBHef2zCoFbTg0TXQeDr5SV7yguX8jB
zZnoNs+6+GR1gA6poKzFdiG4NRr0SNgEHazPPkXp3P2KyOINyFJ7SA+HX8iegTqL
CTPYPK7UNRmb5s2u5B4e9NiQB9L85W4p7p7uemCSu9bxjs8rkCJpvx9Kb8jzPW17
wnEUe10A4JNDBhxiMg+Fm5oM2VxQVy+eDVFOOq7pDYVcSmZc36wO+EwAKph9shby
O4sDS4l/8eQTEYUxTavdtQ9O9ZMXvf/L3Rl1uFJXw1lFwPReXwtpA485e031/A==
=P0jf
-----END PGP MESSAGE-----

--foo--
`)

var testPGPMIMESigned = toCRLF(`From: John Doe <john.doe@example.org>
To: John Doe <john.doe@example.org>
Mime-Version: 1.0
Content-Type: multipart/signed; boundary=bar; micalg=pgp-sha256;
   protocol="application/pgp-signature"

--bar
Content-Type: text/plain

This is a signed message!

--bar
Content-Type: application/pgp-signature

-----BEGIN PGP SIGNATURE-----

iQEzBAABCAAdFiEEsahmk1QVO3mfIhe/MHIVwT33qWQFAl5FRLgACgkQMHIVwT33
qWSEQQf/YgRlKlQzSyvm6A52lGIRU3F/z9EGjhCryxj+hSdPlk8O7iZFIjnco4Ea
7QIlsOj6D4AlLdhyK6c8IZV7rZoTNE5rc6I5UZjM4Qa0XoyLjao28zR252TtwwWJ
e4+wrTQKcVhCyHO6rkvcCpru4qF5CU+Mi8+sf8CNJJyBgw1Pri35rJWMdoTPTqqz
kcIGN1JySaI8bbVitJQmnm0FtFTiB7zznv94rMBCiPmPUWd9BSpSBJteJoBLZ+K7
Y7ws2Dzp2sBo/RLUM18oXd0N9PLXvFGI3IuF8ey1SPzQH3QbBdJSTmLzRlPjK7A1
HVHFb3vTjd71z9j5IGQQ3Awdw30zMg==
=gOul
-----END PGP SIGNATURE-----

--bar--
`)

var testPlaintext = toCRLF(`From: John Doe <john.doe@example.org>
To: John Doe <john.doe@example.org>
Mime-Version: 1.0
Content-Type: text/plain

This is a plaintext message!
`)

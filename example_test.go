package pgpmail_test

import (
	"bytes"
	"io"
	"log"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-pgpmail"
)

func ExampleRead() {
	// Let's assume r contains an e-mail, which is maybe encrypted or signed
	var r io.Reader
	// A private key is needed in case the message is encrypted
	var privateKey *openpgp.Entity

	pgpReader, err := pgpmail.Read(r, openpgp.EntityList{privateKey}, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Header: %v", pgpReader.Header)

	// pgpReader.MessageDetails.UnverifiedBody contains the whole wrapped e-mail
	entity, err := message.Read(pgpReader.MessageDetails.UnverifiedBody)
	if err != nil {
		log.Fatal(err)
	}
	// Do something with the wrapped e-mail
	log.Printf("Wrapped header: %v", entity.Header)
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, entity.Body); err != nil {
		log.Fatal(err)
	}

	// Now that the wrapped e-mail has been read, we can check the signature.
	// We can only do this if the wrapped e-mail has been fully consumed.
	if err := pgpReader.MessageDetails.SignatureError; err != nil {
		log.Fatal(err)
	}

	log.Printf("Signed: %v", pgpReader.MessageDetails.IsSigned)
	log.Printf("Encrypted: %v", pgpReader.MessageDetails.IsEncrypted)
}

func ExampleEncrypt() {
	// to are the recipients' keys, signer is the sender's key
	var to []*openpgp.Entity
	var signer *openpgp.Entity

	var mailHeader mail.Header
	mailHeader.SetAddressList("From", []*mail.Address{{"Mitsuha Miyamizu", "mitsuha.miyamizu@example.org"}})
	mailHeader.SetAddressList("To", []*mail.Address{{"Taki Tachibana", "taki.tachibana@example.org"}})

	var encryptedHeader mail.Header
	encryptedHeader.SetContentType("text/plain", nil)

	encryptedText := "Hi! I'm Mitsuha Miyamizu."

	var buf bytes.Buffer
	cleartext, err := pgpmail.Encrypt(&buf, mailHeader.Header.Header, to, signer, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer cleartext.Close()

	body, err := mail.CreateSingleInlineWriter(cleartext, encryptedHeader)
	if err != nil {
		log.Fatal(err)
	}
	defer body.Close()
	if _, err := io.WriteString(body, encryptedText); err != nil {
		log.Fatal(err)
	}
	if err := body.Close(); err != nil {
		log.Fatal(err)
	}

	if err := cleartext.Close(); err != nil {
		log.Fatal(err)
	}

	log.Print(buf.String())
}

func ExampleSign() {
	// signer is the sender's key
	var signer *openpgp.Entity

	var mailHeader mail.Header
	mailHeader.SetAddressList("From", []*mail.Address{{"Mitsuha Miyamizu", "mitsuha.miyamizu@example.org"}})
	mailHeader.SetAddressList("To", []*mail.Address{{"Taki Tachibana", "taki.tachibana@example.org"}})

	var signedHeader mail.Header
	signedHeader.SetContentType("text/plain", nil)

	signedText := "Hi! I'm Mitsuha Miyamizu."

	var buf bytes.Buffer
	cleartext, err := pgpmail.Sign(&buf, mailHeader.Header.Header, signer, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer cleartext.Close()

	body, err := mail.CreateSingleInlineWriter(cleartext, signedHeader)
	if err != nil {
		log.Fatal(err)
	}
	defer body.Close()
	if _, err := io.WriteString(body, signedText); err != nil {
		log.Fatal(err)
	}
	if err := body.Close(); err != nil {
		log.Fatal(err)
	}

	if err := cleartext.Close(); err != nil {
		log.Fatal(err)
	}

	log.Print(buf.String())
}

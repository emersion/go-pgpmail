package pgpmail_test

import (
	"bytes"
	"io"
	"log"

	"github.com/emersion/go-message"
	"github.com/emersion/go-pgpmail"
	"golang.org/x/crypto/openpgp"
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

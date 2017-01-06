package smtp

import (
	"bytes"
	"io"

	server "github.com/emersion/go-smtp"
	"golang.org/x/crypto/openpgp"

	"github.com/emersion/go-pgpmail/pgpmessage"
)

type user struct {
	server.User

	be *Backend
	kr openpgp.EntityList
}

func (u *user) Send(from string, to []string, r io.Reader) error {
	var pubkeys openpgp.EntityList
	var plaintextTo []string
	var encryptedTo []string
	for _, addr := range to {
		keys, err := u.be.kr.Search("<"+addr+">")
		if err != nil {
			return err
		}

		if len(keys) == 0 {
			plaintextTo = append(plaintextTo, addr)
		} else {
			encryptedTo = append(encryptedTo, addr)

			// TODO: don't always take the first one?
			pubkeys = append(pubkeys, keys[0])
		}
	}

	// Keep a copy of the plaintext message to be able to send it to plaintext
	// recipients too
	plaintext := r
	if len(encryptedTo) > 0 && len(plaintextTo) > 0 {
		b := &bytes.Buffer{}
		r = io.TeeReader(r, b)
		plaintext = b
	}

	// Send encrypted message
	if len(encryptedTo) > 0 {
		// TODO: do not use a buffer here
		b := new(bytes.Buffer)
		if err := pgpmessage.Encrypt(b, r, pubkeys, u.kr[0]); err != nil {
			return err
		}

		if err := u.User.Send(from, encryptedTo, b); err != nil {
			return err
		}
	}

	// Send plaintext message
	if len(plaintextTo) > 0 {
		if err := u.User.Send(from, plaintextTo, plaintext); err != nil {
			return err
		}
	}

	return nil
}

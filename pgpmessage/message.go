package pgpmessage

import (
	"io"
	"log"
	"mime"
	"strings"

	"github.com/emersion/go-message"
	"golang.org/x/crypto/openpgp"
)

func DecryptEntity(e *message.Entity, kr openpgp.KeyRing) (*message.Entity, error) {
	if mr := e.MultipartReader(); mr != nil {
		var parts []*message.Entity

		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			p, err = DecryptEntity(p, kr)
			if err != nil {
				log.Println("WARN: cannot decrypt child part:", err)
				continue
			}

			parts = append(parts, p)
		}

		return message.NewMultipart(e.Header, parts), nil
	} else {
		// A normal part, just decrypt it

		mediaType, _, err := mime.ParseMediaType(e.Header.Get("Content-Type"))
		if err != nil {
			log.Println("WARN: cannot parse Content-Type:", err)
			mediaType = "text/plain"
		}

		isPlainText := strings.HasPrefix(mediaType, "text/")

		var md *openpgp.MessageDetails
		if mediaType == "application/pgp-encrypted" {
			// An encrypted binary part
			md, err = decrypt(e.Body, kr)
		} else if isPlainText {
			// The message text, maybe encrypted with inline PGP
			md, err = decryptArmored(e.Body, kr)
		} else {
			// An unencrypted binary part
			md = &openpgp.MessageDetails{UnverifiedBody: e.Body}
			err = nil
		}
		if err != nil {
			return nil, err
		}

		e := message.NewEntity(e.Header, md.UnverifiedBody)
		if isPlainText {
			e.Header.Set("Content-Transfer-Encoding", "quoted-printable")
		} else {
			e.Header.Set("Content-Transfer-Encoding", "base64")
		}
		return e, nil
	}
}

func EncryptEntity(w io.Writer, e *message.Entity, to []*openpgp.Entity, signed *openpgp.Entity) error {
	// TODO: this function should change headers (e.g. set MIME type to application/pgp-encrypted)

	mw, err := message.CreateWriter(w, e.Header)
	if err != nil {
		return err
	}
	defer mw.Close()

	if mr := e.MultipartReader(); mr != nil {
		// This is a multipart part, parse and encrypt each part

		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			wc, err := mw.CreatePart(e.Header)
			if err != nil {
				return err
			}

			if err := EncryptEntity(wc, p, to, signed); err != nil {
				return err
			}

			wc.Close()
		}
	} else {
		// A normal part, just encrypt it

		disp, _, err := mime.ParseMediaType(e.Header.Get("Content-Disposition"))
		if err != nil {
			log.Println("WARN: cannot parse Content-Disposition:", err)
		}

		var plaintext io.WriteCloser
		if strings.HasPrefix(e.Header.Get("Content-Type"), "text/") && disp != "attachment" {
			// The message text, encrypt it with inline PGP
			plaintext, err = encryptArmored(mw, to, signed)
		} else {
			plaintext, err = encrypt(mw, to, signed)
		}
		if err != nil {
			return err
		}
		defer plaintext.Close()

		if _, err := io.Copy(plaintext, e.Body); err != nil {
			return err
		}
	}

	return nil
}

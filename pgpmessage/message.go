package pgpmessage

import (
	"io"
	"log"
	"mime"
	"strings"

	"github.com/emersion/go-message"
	"golang.org/x/crypto/openpgp"
)

// TODO: properly set Content-Transfer-Encoding

func decryptEntity(mw *message.Writer, e *message.Entity, kr openpgp.KeyRing) error {
	if mr := e.MultipartReader(); mr != nil {
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}

			pw, err := mw.CreatePart(p.Header)
			if err != nil {
				return err
			}

			if err := decryptEntity(pw, p, kr); err != nil {
				log.Println("WARN: cannot decrypt child part:", err)
			}
			pw.Close()
		}
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
			return err
		}

		if _, err := io.Copy(mw, md.UnverifiedBody); err != nil {
			return err
		}

		// Fail if the signature is incorrect
		if err := md.SignatureError; err != nil {
			return err
		}
	}

	return nil
}

func Decrypt(w io.Writer, r io.Reader, kr openpgp.KeyRing) error {
	e, err := message.Read(r)
	if err != nil {
		return err
	}

	mw, err := message.CreateWriter(w, e.Header)
	if err != nil {
		return err
	}
	if err := decryptEntity(mw, e, kr); err != nil {
		return err
	}
	return mw.Close()
}

func encryptEntity(mw *message.Writer, e *message.Entity, to []*openpgp.Entity, signed *openpgp.Entity) error {
	// TODO: this function should change headers (e.g. set MIME type to application/pgp-encrypted)

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

			pw, err := mw.CreatePart(e.Header)
			if err != nil {
				return err
			}

			if err := encryptEntity(pw, p, to, signed); err != nil {
				return err
			}
			pw.Close()
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

func Encrypt(w io.Writer, r io.Reader, to []*openpgp.Entity, signed *openpgp.Entity) error {
	e, err := message.Read(r)
	if err != nil {
		return err
	}

	mw, err := message.CreateWriter(w, e.Header)
	if err != nil {
		return err
	}
	if err := encryptEntity(mw, e, to, signed); err != nil {
		return err
	}
	return mw.Close()
}

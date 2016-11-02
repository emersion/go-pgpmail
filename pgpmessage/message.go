package pgpmessage

import (
	"io"
	"log"
	"mime"
	"strings"

	"github.com/emersion/go-pgpmail/message"
	"golang.org/x/crypto/openpgp"
)

func DecryptPart(p *message.Part, kr openpgp.KeyRing) (*message.Part, error) {
	mr := p.ChildrenReader()
	if mr != nil {
		// This is a multipart part, parse and decrypt each part

		pr, pw := io.Pipe()

		var mw *message.Writer
		p.Header, mw = message.NewWriter(pw, p.Header)

		go func() {
			defer mw.Close()

			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					pw.CloseWithError(err)
					return
				}

				p, err = DecryptPart(p, kr)
				if err != nil {
					log.Println("WARN: cannot decrypt child part:", err)
					continue
				}

				wc, err := mw.CreateChild(p.Header)
				if err != nil {
					pw.CloseWithError(err)
					return
				}

				if _, err := io.Copy(wc, p); err != nil {
					log.Println("WARN: cannot decrypt child part:", err)
					continue
				}

				wc.Close()
			}

			pw.Close()
		}()

		return message.NewPart(p.Header, pr), nil
	} else {
		// A normal part, just decrypt it

		mediaType, _, err := mime.ParseMediaType(p.Header.Get("Content-Type"))
		if err != nil {
			log.Println("WARN: cannot parse Content-Type:", err)
			mediaType = "text/plain"
		}

		isPlainText := strings.HasPrefix(mediaType, "text/")

		var md *openpgp.MessageDetails
		if mediaType == "application/pgp-encrypted" {
			// An encrypted binary part
			md, err = decrypt(p, kr)
		} else if isPlainText {
			// The message text, maybe encrypted with inline PGP
			md, err = decryptArmored(p, kr)
		} else {
			// An unencrypted binary part
			md = &openpgp.MessageDetails{UnverifiedBody: p}
			err = nil
		}
		if err != nil {
			return nil, err
		}

		p := message.NewPart(p.Header, md.UnverifiedBody)
		if isPlainText {
			p.Header.Set("Content-Transfer-Encoding", "quoted-printable")
		} else {
			p.Header.Set("Content-Transfer-Encoding", "base64")
		}
		return p, nil
	}

	return p, nil
}

func EncryptPart(w io.Writer, p *message.Part, to []*openpgp.Entity, signed *openpgp.Entity) error {
	// TODO: this function should change headers (e.g. set MIME type to application/pgp-encrypted)

	mw, err := message.CreateWriter(w, p.Header)
	if err != nil {
		return err
	}
	defer mw.Close()

	mr := p.ChildrenReader()
	if mr != nil {
		// This is a multipart part, parse and encrypt each part

		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			wc, err := mw.CreateChild(p.Header)
			if err != nil {
				return err
			}

			if err := EncryptPart(wc, p, to, signed); err != nil {
				return err
			}

			wc.Close()
		}
	} else {
		// A normal part, just encrypt it

		disp, _, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		if err != nil {
			log.Println("WARN: cannot parse Content-Disposition:", err)
		}

		var plaintext io.WriteCloser
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/") && disp != "attachment" {
			// The message text, encrypt it with inline PGP
			plaintext, err = encryptArmored(mw, to, signed)
		} else {
			plaintext, err = encrypt(mw, to, signed)
		}
		if err != nil {
			return err
		}
		defer plaintext.Close()

		if _, err := io.Copy(plaintext, p); err != nil {
			return err
		}
	}

	return nil
}

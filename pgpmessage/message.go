package pgpmessage

import (
	"io"
	"log"
	"mime"
	"mime/multipart"
	"strings"

	"github.com/emersion/go-imap-pgp/message"
	"golang.org/x/crypto/openpgp"
)

func DecryptPart(p *message.Part, kr openpgp.KeyRing) (*message.Part, error) {
	mediaType, mediaParams, err := mime.ParseMediaType(p.Header.Get("Content-Type"))
	if err != nil {
		log.Println("WARN: cannot parse Content-Type:", err)
		mediaType = "text/plain"
	}

	mr := p.ChildrenReader()
	if mr != nil {
		// This is a multipart part, parse and decrypt each part

		pr, pw := io.Pipe()

		go func() {
			mw := multipart.NewWriter(pw)
			mw.SetBoundary(mediaParams["boundary"])
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

				w, err := mw.CreatePart(p.Header)
				if err != nil {
					pw.CloseWithError(err)
					return
				}

				if _, err := io.Copy(w, p); err != nil {
					log.Println("WARN: cannot decrypt child part:", err)
					continue
				}
			}
		}()

		return message.NewPart(p.Header, pr), nil
	} else {
		// A normal part, just decrypt it

		disp, _, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		if err != nil {
			log.Println("WARN: cannot parse Content-Disposition:", err)
			disp = "attachment"
		}

		var md *openpgp.MessageDetails
		if mediaType == "application/pgp-encrypted" {
			// An encrypted binary part
			md, err = decrypt(p, kr)
		} else if strings.HasPrefix(mediaType, "text/") && disp != "attachment" {
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

		return message.NewPart(p.Header, md.UnverifiedBody), nil
	}

	return p, nil
}

func EncryptPart(w io.Writer, p *message.Part, to []*openpgp.Entity, signed *openpgp.Entity) error {
	mr := p.ChildrenReader()
	if mr != nil {
		// This is a multipart part, parse and encrypt each part

		mw, err := message.CreateMultipart(w, p.Header)
		if err != nil {
			return err
		}
		defer mw.Close()

		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			w, err := mw.CreatePart(p.Header)
			if err != nil {
				return err
			}

			if err := EncryptPart(w, p, to, signed); err != nil {
				return err
			}
		}
	} else {
		// A normal part, just encrypt it

		disp, _, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		if err != nil {
			log.Println("WARN: cannot parse Content-Disposition:", err)
			disp = "attachment"
		}

		w, err := message.CreatePart(w, p.Header)
		if err != nil {
			return err
		}
		defer w.Close()

		var plaintext io.WriteCloser
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/") && disp != "attachment" {
			// The message text, encrypt it with inline PGP
			plaintext, err = encryptArmored(w, to, signed)
		} else {
			plaintext, err = encrypt(w, to, signed)
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

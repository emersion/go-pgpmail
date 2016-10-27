package openpgp

import (
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"

	"golang.org/x/crypto/openpgp"
)

func decryptPart(kr openpgp.KeyRing, h textproto.MIMEHeader, r io.Reader) (textproto.MIMEHeader, io.Reader, error) {
	mediaType, mediaParams, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		log.Println("WARN: cannot parse Content-Type:", err)
		mediaType = "text/plain"
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		// This is a multipart part, parse and decrypt each part

		pr, pw := io.Pipe()

		go func() {
			mr := multipart.NewReader(r, mediaParams["boundary"])

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

				h, r, err := decryptPart(kr, p.Header, p)
				if err != nil {
					log.Println("WARN: cannot decrypt part:", err)
					continue
				}

				w, err := mw.CreatePart(h)
				if err != nil {
					pw.CloseWithError(err)
					return
				}

				if _, err := io.Copy(w, r); err != nil {
					pw.CloseWithError(err)
					return
				}
			}
		}()

		return h, pr, nil
	} else {
		// A normal part, just decrypt it

		disp, _, err := mime.ParseMediaType(h.Get("Content-Disposition"))
		if err != nil {
			log.Println("WARN: cannot parse Content-Disposition:", err)
			disp = "attachment"
		}

		if mediaType == "application/pgp-encrypted" {
			// An encrypted binary part
			md, err := openpgp.ReadMessage(r, kr, nil, nil)
			if err != nil {
				return nil, nil, err
			}

			return h, md.UnverifiedBody, nil
		} else if strings.HasPrefix(mediaType, "text/") && disp != "attachment" {
			// The message text, maybe encrypted with inline PGP
			r, err := decryptArmored(kr, r)
			if err != nil {
				return nil, nil, err
			}

			return h, r, nil
		}
	}

	return h, r, nil
}

func DecryptPart(kr openpgp.KeyRing, p *multipart.Part) (textproto.MIMEHeader, io.Reader, error) {
	return decryptPart(kr, p.Header, p)
}

func DecryptMessage(kr openpgp.KeyRing, msg *mail.Message) (*mail.Message, error) {
	h, r, err := decryptPart(kr, textproto.MIMEHeader(msg.Header), msg.Body)
	if err != nil {
		return nil, err
	}

	return &mail.Message{
		Header: mail.Header(h),
		Body: r,
	}, nil
}

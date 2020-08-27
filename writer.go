package pgpmail

import (
	"bytes"
	"fmt"
	"io"
	"mime"

	"github.com/emersion/go-message/textproto"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/text/transform"
)

// for tests
var forceBoundary = ""

type multiCloser []io.Closer

func (mc multiCloser) Close() error {
	for _, c := range mc {
		if err := c.Close(); err != nil {
			return err
		}
	}
	return nil
}

func Encrypt(w io.Writer, h textproto.Header, to []*openpgp.Entity, signed *openpgp.Entity, config *packet.Config) (io.WriteCloser, error) {
	mw := textproto.NewMultipartWriter(w)

	if forceBoundary != "" {
		mw.SetBoundary(forceBoundary)
	}

	params := map[string]string{
		"boundary": mw.Boundary(),
		"protocol": "application/pgp-encrypted",
	}
	h.Set("Content-Type", mime.FormatMediaType("multipart/encrypted", params))

	if err := textproto.WriteHeader(w, h); err != nil {
		return nil, err
	}

	var controlHeader textproto.Header
	controlHeader.Set("Content-Type", "application/pgp-encrypted")
	controlWriter, err := mw.CreatePart(controlHeader)
	if err != nil {
		return nil, err
	}
	if _, err := controlWriter.Write([]byte("Version: 1\r\n")); err != nil {
		return nil, err
	}

	var encryptedHeader textproto.Header
	encryptedHeader.Set("Content-Type", "application/octet-stream")
	encryptedWriter, err := mw.CreatePart(encryptedHeader)
	if err != nil {
		return nil, err
	}

	// armor uses LF lines endings, but we need CRLF
	crlfWriter := transform.NewWriter(encryptedWriter, &crlfTransformer{})

	armorWriter, err := armor.Encode(crlfWriter, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}

	plaintext, err := openpgp.Encrypt(armorWriter, to, signed, nil, config)
	if err != nil {
		return nil, err
	}

	return struct {
		io.Writer
		io.Closer
	}{
		plaintext,
		multiCloser{
			plaintext,
			armorWriter,
			mw,
		},
	}, nil
}

type signer struct {
	io.Writer
	pw     *io.PipeWriter
	done   <-chan error
	sigBuf bytes.Buffer
	mw     *textproto.MultipartWriter
}

func (s *signer) Close() error {
	// Close the pipe to let openpgp.DetachSign finish
	if err := s.pw.Close(); err != nil {
		return err
	}
	if err := <-s.done; err != nil {
		return err
	}
	// At this point s.sigBuf contains the complete signature

	var sigHeader textproto.Header
	sigHeader.Set("Content-Type", "application/pgp-signature")
	sigWriter, err := s.mw.CreatePart(sigHeader)
	if err != nil {
		return err
	}

	// armor uses LF lines endings, but we need CRLF
	crlfWriter := transform.NewWriter(sigWriter, &crlfTransformer{})

	armorWriter, err := armor.Encode(crlfWriter, "PGP MESSAGE", nil)
	if err != nil {
		return err
	}

	if _, err := io.Copy(armorWriter, &s.sigBuf); err != nil {
		return err
	}

	if err := armorWriter.Close(); err != nil {
		return err
	}
	return s.mw.Close()
}

func Sign(w io.Writer, header, signedHeader textproto.Header, signed *openpgp.Entity, config *packet.Config) (io.WriteCloser, error) {
	mw := textproto.NewMultipartWriter(w)

	if forceBoundary != "" {
		mw.SetBoundary(forceBoundary)
	}

	var micalg string
	for name, hash := range hashAlgs {
		if hash == config.Hash() {
			micalg = name
			break
		}
	}
	if micalg == "" {
		return nil, fmt.Errorf("pgpmail: unknown hash algorithm %v", config.Hash())
	}

	params := map[string]string{
		"boundary": mw.Boundary(),
		"protocol": "application/pgp-signature",
		"micalg":   micalg,
	}
	header.Set("Content-Type", mime.FormatMediaType("multipart/signed", params))

	if err := textproto.WriteHeader(w, header); err != nil {
		return nil, err
	}

	signedWriter, err := mw.CreatePart(signedHeader)
	if err != nil {
		return nil, err
	}
	// TODO: canonicalize text written to signedWriter

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	s := &signer{
		Writer: io.MultiWriter(pw, signedWriter),
		pw:     pw,
		done:   done,
		mw:     mw,
	}

	go func() {
		done <- openpgp.DetachSign(&s.sigBuf, signed, pr, config)
	}()

	if err := textproto.WriteHeader(pw, signedHeader); err != nil {
		pw.Close()
		return nil, err
	}

	return s, nil
}

// crlfTranformer transforms lone LF characters with CRLF.
type crlfTransformer struct {
	cr bool
}

func (tr *crlfTransformer) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	for _, c := range src {
		if c == '\r' {
			tr.cr = true
		}

		if c == '\n' {
			if tr.cr {
				tr.cr = false
			} else {
				if nDst+1 >= len(dst) {
					err = transform.ErrShortDst
					break
				}
				dst[nDst] = '\r'
				nDst++
			}
		}

		if nDst >= len(dst) {
			err = transform.ErrShortDst
			break
		}
		dst[nDst] = c
		nDst++
		nSrc++
	}
	return nDst, nSrc, err
}

func (tr *crlfTransformer) Reset() {
	tr.cr = false
}

var _ transform.Transformer = (*crlfTransformer)(nil)

package pgpmail

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"mime"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/emersion/go-message/textproto"
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

	if !h.Has("Mime-Version") {
		h.Set("Mime-Version", "1.0")
	}

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

	plaintext, err := openpgp.EncryptText(armorWriter, to, signed, nil, config)
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
	closed bool
}

func (s *signer) Close() error {
	if s.closed {
		return fmt.Errorf("pgpmail: signer already closed")
	}
	s.closed = true

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

func Sign(w io.Writer, header textproto.Header, signed *openpgp.Entity, config *packet.Config) (io.WriteCloser, error) {
	// We need to grab the header written to the returned io.WriteCloser, then
	// use it to create a new part in the multipart/signed message

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

	if !header.Has("Mime-Version") {
		header.Set("Mime-Version", "1.0")
	}

	if err := textproto.WriteHeader(w, header); err != nil {
		return nil, err
	}

	handleHeader := func(signedHeader textproto.Header) (io.WriteCloser, error) {
		signedHeader.Del("Mime-Version")

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
			err := openpgp.DetachSignText(&s.sigBuf, signed, pr, config)
			// Close the pipe to make sure textproto.WriteHeader doesn't block
			pr.CloseWithError(err)
			done <- err
		}()

		if err := textproto.WriteHeader(pw, signedHeader); err != nil {
			pw.Close()
			return nil, err
		}

		return s, nil
	}

	return &headerWriter{handle: handleHeader}, nil
}

var (
	doubleCRLF = []byte("\r\n\r\n")
	doubleLF   = []byte("\n\n")
)

func hasDoubleCRLFSuffix(b []byte) bool {
	return bytes.HasSuffix(b, doubleCRLF) || bytes.HasSuffix(b, doubleLF)
}

// headerWriter collects a header written to itself, calls handle, and writes the
// body to the returned io.WriteCloser.
//
// If handle returns an io.WriteCloser, its Close method is guaranteed to be
// called when the headerWriter is closed.
type headerWriter struct {
	handle func(textproto.Header) (io.WriteCloser, error)

	headerBuf      bytes.Buffer
	headerComplete bool
	bodyWriter     io.WriteCloser
	err            error
}

func (hw *headerWriter) Write(buf []byte) (int, error) {
	if hw.headerComplete {
		if hw.err != nil {
			return 0, hw.err
		}
		return hw.bodyWriter.Write(buf)
	}

	hw.headerBuf.Grow(len(buf))

	gotDoubleCRLF := false
	N := 0
	for _, b := range buf {
		hw.headerBuf.WriteByte(b)
		N++

		if b == '\n' && hasDoubleCRLFSuffix(hw.headerBuf.Bytes()) {
			gotDoubleCRLF = true
			break
		}
	}

	if gotDoubleCRLF {
		if err := hw.parseHeader(); err != nil {
			return N, err
		}

		n, err := hw.bodyWriter.Write(buf[N:])
		return N + n, err
	}

	return N, nil
}

func (hw *headerWriter) Close() error {
	// Ensure we always close the underlying io.WriterCloser, to avoid leaking
	// resources
	if hw.bodyWriter != nil {
		defer hw.bodyWriter.Close()
	}

	if !hw.headerComplete {
		if err := hw.parseHeader(); err != nil {
			return err
		}
	}

	if hw.err != nil {
		return hw.err
	}
	return hw.bodyWriter.Close()
}

func (hw *headerWriter) parseHeader() error {
	hw.headerComplete = true

	h, err := textproto.ReadHeader(bufio.NewReader(&hw.headerBuf))
	if err != nil {
		hw.err = err
		return err
	}

	hw.bodyWriter, hw.err = hw.handle(h)
	return hw.err
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

package message

import (
	"encoding/base64"
	"io"
	"mime/quotedprintable"
	"strings"
)

func decodeEncoding(r io.Reader, enc string) io.Reader {
	switch strings.ToLower(enc) {
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	}
	return r
}

type nopWriteCloser struct {
	io.Writer
}

func (wc *nopWriteCloser) Close() error {
	return nil
}

func encodeEncoding(w io.Writer, enc string) io.WriteCloser {
	var wc io.WriteCloser
	switch strings.ToLower(enc) {
	case "quoted-printable":
		wc = quotedprintable.NewWriter(w)
	case "base64":
		wc = base64.NewEncoder(base64.StdEncoding, w)
	default:
		wc = &nopWriteCloser{w}
	}
	return wc
}

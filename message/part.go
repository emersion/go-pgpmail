package message

import (
	"bufio"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
)

type Part struct {
	io.Reader

	Header textproto.MIMEHeader
}

func NewPart(h textproto.MIMEHeader, r io.Reader) *Part {
	switch h.Get("Content-Transfer-Encoding") {
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	}
	h.Del("Content-Transfer-Encoding")

	return &Part{r, h}
}

func ReadPart(r io.Reader) (*Part, error) {
	br := bufio.NewReader(r)
	h, err := textproto.NewReader(br).ReadMIMEHeader()
	if err != nil {
		return nil, err
	}

	return NewPart(h, br), nil
}

func (p *Part) ChildrenReader() *Reader {
	t, params, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
	if !strings.HasPrefix(t, "multipart/") {
		return nil
	}

	return &Reader{multipart.NewReader(p, params["boundary"])}
}

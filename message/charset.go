package message

import (
	"io"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
)

var charsets = map[string]encoding.Encoding{
	"iso-8859-1": charmap.ISO8859_1,
	"windows-1252": charmap.Windows1252,
}

func decodeCharset(r io.Reader, charset string) io.Reader {
	if enc, ok := charsets[strings.ToLower(charset)]; ok {
		r = enc.NewDecoder().Reader(r)
	}

	return r
}

package pgpmail

import (
	"bufio"
	"bytes"
	"crypto"
	"fmt"
	"hash"
	"io"
	"mime"
	"strings"

	"github.com/emersion/go-message/textproto"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type Reader struct {
	Header         textproto.Header
	MessageDetails *openpgp.MessageDetails
}

func NewReader(h textproto.Header, body io.Reader, keyring openpgp.KeyRing, prompt openpgp.PromptFunction, config *packet.Config) (*Reader, error) {
	t, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		return nil, err
	}

	if strings.EqualFold(t, "multipart/encrypted") && strings.EqualFold(params["protocol"], "application/pgp-encrypted") {
		mr := textproto.NewMultipartReader(body, params["boundary"])
		return newEncryptedReader(h, mr, keyring, prompt, config)
	}
	if strings.EqualFold(t, "multipart/signed") && strings.EqualFold(params["protocol"], "application/pgp-signature") {
		micalg := params["micalg"]
		mr := textproto.NewMultipartReader(body, params["boundary"])
		return newSignedReader(h, mr, micalg, keyring, prompt, config)
	}

	var headerBuf bytes.Buffer
	textproto.WriteHeader(&headerBuf, h)

	return &Reader{
		Header: h,
		MessageDetails: &openpgp.MessageDetails{
			UnverifiedBody: io.MultiReader(&headerBuf, body),
		},
	}, nil
}

func Read(r io.Reader, keyring openpgp.KeyRing, prompt openpgp.PromptFunction, config *packet.Config) (*Reader, error) {
	br := bufio.NewReader(r)

	h, err := textproto.ReadHeader(br)
	if err != nil {
		return nil, err
	}

	return NewReader(h, br, keyring, prompt, config)
}

func newEncryptedReader(h textproto.Header, mr *textproto.MultipartReader, keyring openpgp.KeyRing, prompt openpgp.PromptFunction, config *packet.Config) (*Reader, error) {
	p, err := mr.NextPart()
	if err != nil {
		return nil, fmt.Errorf("pgpmail: failed to read first part in multipart/encrypted message: %v", err)
	}

	t, _, err := mime.ParseMediaType(p.Header.Get("Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("pgpmail: failed to parse Content-Type of first part in multipart/encrypted message: %v", err)
	}
	if !strings.EqualFold(t, "application/pgp-encrypted") {
		return nil, fmt.Errorf("pgpmail: first part in multipart/encrypted message has type %q, not application/pgp-encrypted", t)
	}

	metadata, err := textproto.ReadHeader(bufio.NewReader(p))
	if err != nil {
		return nil, fmt.Errorf("pgpmail: failed to parse application/pgp-encrypted part: %v", err)
	}
	if s := metadata.Get("Version"); s != "1" {
		return nil, fmt.Errorf("pgpmail: unsupported PGP/MIME version: %q", s)
	}

	p, err = mr.NextPart()
	if err != nil {
		return nil, fmt.Errorf("pgpmail: failed to read second part in multipart/encrypted message: %v", err)
	}
	t, _, err = mime.ParseMediaType(p.Header.Get("Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("pgpmail: failed to parse Content-Type of second part in multipart/encrypted message: %v", err)
	}
	if !strings.EqualFold(t, "application/octet-stream") {
		return nil, fmt.Errorf("pgpmail: second part in multipart/encrypted message has type %q, not application/octet-stream", t)
	}

	block, err := armor.Decode(p)
	if err != nil {
		return nil, fmt.Errorf("pgpmail: failed to parse encrypted armored data: %v", err)
	}

	md, err := openpgp.ReadMessage(block.Body, keyring, prompt, config)
	if err != nil {
		return nil, fmt.Errorf("pgpmail: failed to read PGP message: %v", err)
	}

	return &Reader{
		Header:         h,
		MessageDetails: md,
	}, nil
}

type signedReader struct {
	keyring   openpgp.KeyRing
	multipart *textproto.MultipartReader
	signed    io.Reader
	hashFunc  crypto.Hash
	hash      hash.Hash
	md        *openpgp.MessageDetails
}

func (r *signedReader) Read(b []byte) (int, error) {
	n, err := r.signed.Read(b)
	r.hash.Write(b[:n])
	if err == io.EOF {
		r.md.SignatureError = r.check()
	}
	return n, err
}

func (r *signedReader) check() error {
	part, err := r.multipart.NextPart()
	if err != nil {
		return fmt.Errorf("pgpmail: failed to read signature part of multipart/signed message: %v", err)
	}

	t, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
	if err != nil {
		return fmt.Errorf("pgpmail: failed to parse Content-Type of signature part in multipart/encrypted message: %v", err)
	}
	if !strings.EqualFold(t, "application/pgp-signature") {
		return fmt.Errorf("pgpmail: signature part in multipart/encrypted message has type %q, not application/pgp-signature", t)
	}

	block, err := armor.Decode(part)
	if err != nil {
		return fmt.Errorf("pgpmail: failed to read armored signature block: %v", err)
	}

	var p packet.Packet
	var keys []openpgp.Key
	var sigErr error
	pr := packet.NewReader(block.Body)
	for {
		p, err = pr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("pgpmail: failed to read signature: %v", err)
		}

		var issuerKeyId uint64
		var hashFunc crypto.Hash
		switch sig := p.(type) {
		case *packet.Signature:
			if sig.IssuerKeyId == nil {
				return fmt.Errorf("pgpmail: signature doesn't have an issuer")
			}
			issuerKeyId = *sig.IssuerKeyId
			hashFunc = sig.Hash
		case *packet.SignatureV3:
			issuerKeyId = sig.IssuerKeyId
			hashFunc = sig.Hash
		default:
			return fmt.Errorf("pgpmail: non signature packet found")
		}

		r.md.SignedByKeyId = issuerKeyId

		if hashFunc != r.hashFunc {
			return fmt.Errorf("pgpmail: micalg mismatch: multipart header indicates %v but signature packet indicates %v", r.hashFunc, hashFunc)
		}

		keys = r.keyring.KeysByIdUsage(issuerKeyId, packet.KeyFlagSign)
		if len(keys) == 0 {
			continue
		}

		for i, key := range keys {
			switch sig := p.(type) {
			case *packet.Signature:
				sigErr = key.PublicKey.VerifySignature(r.hash, sig)
			case *packet.SignatureV3:
				sigErr = key.PublicKey.VerifySignatureV3(r.hash, sig)
			default:
				panic("unreachable")
			}

			if sigErr == nil {
				r.md.SignedBy = &keys[i]
				return nil
			}
		}
	}

	if sigErr != nil {
		return sigErr
	}
	return fmt.Errorf("pgpmail: unknown issuer")
}

func newSignedReader(h textproto.Header, mr *textproto.MultipartReader, micalg string, keyring openpgp.KeyRing, prompt openpgp.PromptFunction, config *packet.Config) (*Reader, error) {
	hashFunc, ok := hashAlgs[micalg]
	if !ok {
		return nil, fmt.Errorf("pgpmail: unsupported micalg %q", micalg)
	}

	if !hashFunc.Available() {
		return nil, fmt.Errorf("pgpmail: micalg %q unavailable", micalg)
	}
	hash := hashFunc.New()

	p, err := mr.NextPart()
	if err != nil {
		return nil, fmt.Errorf("pgpmail: failed to read signed part in multipart/signed message: %v", err)
	}

	var headerBuf bytes.Buffer
	textproto.WriteHeader(&headerBuf, p.Header)

	// TODO: convert line endings to CRLF

	md := &openpgp.MessageDetails{IsSigned: true}

	sr := &signedReader{
		keyring:   keyring,
		multipart: mr,
		signed:    io.MultiReader(&headerBuf, p),
		hashFunc:  hashFunc,
		hash:      hash,
		md:        md,
	}
	md.UnverifiedBody = sr

	return &Reader{
		Header:         h,
		MessageDetails: md,
	}, nil
}
